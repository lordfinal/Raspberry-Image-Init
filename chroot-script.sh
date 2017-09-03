#!/bin/bash
cat <<EOF > /etc/init.d/imagebootscript.sh
#!/bin/bash
echo \$PWD
echo $PWD

NEEDED_PACKAGES=(git openvpn)


function check_install_package {
  PKG_OK=\$(dpkg-query -W --showformat='\${Status}\n' \$1 | grep "install ok installed")
  if [ "" == "\$PKG_OK" ]; then
    sudo apt-get --force-yes --yes install \$1
  fi
}


for pkg in "\${NEEDED_PACKAGES[@]}"; do
  check_install_package(\$pkg)
done
EOF



Bootscript
cronjob 
  for checking if git is installed 
  pull latest repo
  install vpn config
  execute a specific script from the repo
