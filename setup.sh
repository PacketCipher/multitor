#!/usr/bin/env bash

readonly _dir="$(dirname "$(readlink -f "$0")")"

# shellcheck disable=SC2034
_arg="$1"

if [[ "$1" == "install" ]] ; then

  printf "%s\\n" "Create symbolic link to /usr/local/bin"

  if [[ -e "${_dir}/bin/multitor" ]] ; then

    if [[ ! -e "/usr/local/bin/multitor" ]] ; then

      ln -s "${_dir}/bin/multitor" /usr/local/bin

    fi

  fi

  printf "%s\\n" "Create man page to /usr/local/man/man8"

  if [[ -e "${_dir}/static/man8/multitor.8" ]] ; then

    if [[ ! -e "/usr/local/man/man8/multitor.8.gz" ]] ; then

      mkdir -p /usr/local/man/man8
      cp "${_dir}/static/man8/multitor.8" /usr/local/man/man8
      gzip /usr/local/man/man8/multitor.8

    fi

  fi

  # Install Python dependencies for custom_lb
  printf "\\n%s\\n" "Checking and installing Python dependencies (requests, pysocks)..."
  if command -v apt-get &> /dev/null; then
    if dpkg -s python3-requests &> /dev/null && dpkg -s python3-pysocks &> /dev/null && dpkg -s tor &> /dev/null; then
      printf "%s\\n" "Python and Tor dependencies already satisfied."
    else
      printf "%s\\n" "Attempting to install tor, python3-requests, and python3-pysocks..."
      # Run update once
      apt-get update -qq
      if apt-get install -y tor python3-requests python3-pysocks; then
        printf "%s\\n" "Successfully installed tor, python3-requests, and python3-pysocks."
      else
        printf "%s\\n" "WARNING: Failed to install some dependencies (tor, python3-requests, python3-pysocks). Required features may not work."
        printf "%s\\n" "Please try installing them manually (e.g., sudo apt-get install tor python3-requests python3-pysocks)."
      fi
    fi
  else
    printf "%s\\n" "WARNING: 'apt-get' not found. Cannot automatically install Python dependencies."
    printf "%s\\n" "Please ensure 'python3-requests' and 'python3-pysocks' are installed for custom_lb functionality."
  fi
  printf "%s\\n" "--------------------------------------------------------------------"


elif [[ "$1" == "uninstall" ]] ; then

  printf "%s\\n" "Remove symbolic link from /usr/local/bin"

  if [[ -L "/usr/local/bin/multitor" ]] ; then

    unlink /usr/local/bin/multitor

  fi

  printf "%s\\n" "Remove man page from /usr/local/man/man8"

  if [[ -e "/usr/local/man/man8/multitor.8.gz" ]] ; then

    rm /usr/local/man/man8/multitor.8.gz

  fi

else

  printf "Usage:\\n  ./setup.sh install     (Install)\\n  ./setup.sh uninstall   (Uninstall)\\n"

fi

exit 0
