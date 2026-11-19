#!/usr/bin/env bash
# Publishes this folder as a PUBLIC GitHub repository.
#   ./publish.sh            repository name "sthir"
#   ./publish.sh my-name    another name
# Before this: pkg install git gh   and   gh auth login
set -e
cd "$(dirname "$0")"
NAME="${1:-sthir}"
command -v git >/dev/null || { echo "Install git first:  pkg install git"; exit 1; }
command -v gh  >/dev/null || { echo "Install the GitHub tool first:  pkg install gh"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Log in to GitHub first:  gh auth login   (choose GitHub.com, HTTPS, login with a web browser)"; exit 1; }

[ -d .git ] || git init -q -b main
USER_LOGIN=$(gh api user -q .login)
USER_ID=$(gh api user -q .id)
EMAIL="$(git config user.email || true)"
[ -n "$(git config user.name || true)" ] || git config user.name "$USER_LOGIN"
if [ -z "$EMAIL" ]; then
  EMAIL="$USER_ID+$USER_LOGIN@users.noreply.github.com"   # GitHub's private address
  git config user.email "$EMAIL"
fi

echo "GitHub account : $USER_LOGIN"
echo "Repository     : https://github.com/$USER_LOGIN/$NAME   (PUBLIC: anyone in the world can read it)"
echo "Commits will show the email: $EMAIL"
case "$EMAIL" in *noreply.github.com) ;; *) echo "  ^ this is a real address and it becomes public. To hide it:"
  echo "    git config user.email \"$USER_ID+$USER_LOGIN@users.noreply.github.com\"  and run again.";; esac

# Safety: refuse to publish keys or personal data.
BAD=$(find . -path ./.git -prune -o \( -name '*.key' -o -name 'accounts.json*' -o -name 'miner.addr' -o -name '*.removed' -o -name 'sthir-data' -o -name 'wallet-backups' \) -print)
if [ -n "$BAD" ]; then
  echo "STOP: these files look private and must not be published:"; echo "$BAD"
  echo "They are in .gitignore, so git will skip them, but check that you meant it. Move them away and run again."
  [ "${PUBLISH_FORCE:-}" = 1 ] || exit 1
fi

if [ "${PUBLISH_YES:-}" != 1 ]; then
  printf "Publish now? Type YES to continue: "; read -r A
  [ "$A" = "YES" ] || { echo "Cancelled. Nothing was published."; exit 1; }
fi

sed -i "s/{{GITHUB_USER}}/$USER_LOGIN/g" README.md
git add -A
git ls-files | grep -E '(^|/)(.*\.key|accounts\.json.*|miner\.addr)$' && { echo "STOP: a private file got staged."; exit 1; } || true
git commit -q -m "Sthir 0.1.0: experimental wallet, chain, offline vouchers and proofs" || true
gh repo create "$NAME" --public --source=. --remote=origin --push \
  --description "Experimental proof-of-work coin and wallet for phones (Termux). Research project, not an investment."
gh repo edit "$USER_LOGIN/$NAME" --add-topic blockchain --add-topic python --add-topic termux --add-topic experimental >/dev/null 2>&1 || true
gh api -X PUT "repos/$USER_LOGIN/$NAME/private-vulnerability-reporting" >/dev/null 2>&1 || echo "Note: turn on Settings > Code security > Private vulnerability reporting by hand."
git tag -f v0.1.0 >/dev/null && git push -q origin v0.1.0 2>/dev/null || true
gh release create v0.1.0 --prerelease --title "Sthir 0.1.0 (experimental)" \
  --notes "First public release. Research code: no live network, no value, unaudited. Read README.md and SECURITY.md first." >/dev/null 2>&1 || true

echo
echo "Done. Your repository: https://github.com/$USER_LOGIN/$NAME"
echo "Anyone can install it with:"
echo "  pkg install -y git python python-cryptography"
echo "  git clone https://github.com/$USER_LOGIN/$NAME"
echo "  cd $NAME && ./setup.sh"
