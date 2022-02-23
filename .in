#!/usr/bin/env bash
echo -e "\033[1;36m
 _____  __  __   _____                _
/__   \/ / / _\ /__   \_ __ _   _ ___| |_
  / /\/ /  \ \    / /\/ '__| | | / __| __|
 / / / /____\ \  / /  | |  | |_| \__ \ |_
 \/  \____/\__/  \/   |_|   \__,_|___/\__|\033[0m"


git fetch
git status
echo

if [[ -f "$(which git-secrets 2>/dev/null)" ]]; then
  git-secrets --scan
else
  echo -e "\033[1;31mPlease install git-secrets \033[0m"
fi
echo -e "\033[1;36m$(make --version)\033[0m\n$(make help)"
