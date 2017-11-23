#!/bin/bash

RESPBIAN_FILENAME=respbian.zip
RESPBIAN_EXTRACT_DIR=./
RESPBIAN_CONFIG_DIR=${RESPBIAN_EXTRACT_DIR}config
OPTION_FILE=${RESPBIAN_CONFIG_DIR}/raspi-options.sh

RESPBIAN_IMG_NAME=''
RESPBIAN_MOUNT_DIR=./mounted
BLOCK_SIZE=512
RASPBIAN_SD_CARD=''
RESPBIAN_HOSTNAME=bro-ids-first
GITLAB_PRIVATE_TOKEN=
GITLAB_HOST=
EMULATION_QEMU_BINARY="qemu-system-arm"
RESPBIAN_IMAGE_MIN_SIZE_MB=3900

OPENVPN_CA_FILE=
OPENVPN_CERT_FILE=
OPENVPN_KEY_FILE=
OPENVPN_CONFIG_FILE=
OPENVPN_SERVICE_NAME=

STAT_CMD=/usr/bin/stat
FDISK_CMD=/sbin/fdisk
CP=`which rsync | head -n1`

if [-z "${CP}"]; then
  CP="${CP} --progress "
else
  CP="cp "
fi


if [ -e "${OPTION_FILE}" ]; then
  source ${OPTION_FILE}
else
  echo "Not option file at: ${OPTION_FILE}"
fi

exit 0

function log () {
  if [[ $VERBOSE -eq 1 ]]; then
      echo -e "\e[92m$@\e[39m"
  fi
}

function wait_for_newline () {
  #for stopping the script during execution; for debugging
  read  -n 1 -p "Wait for newline"
}

function download_rasbian_archive {
  if [ -z "${RESPBIAN_FILENAME_PRESET}" ]; then 
    #download archive
    log "Downloading Respbian image"
    wget https://downloads.raspberrypi.org/raspbian_lite_latest -O ${RESPBIAN_FILENAME}
  else 
    RESPBIAN_FILENAME=${RESPBIAN_FILENAME_PRESET}
  fi
}

function extract_rasbian_image {
  #get img filename
  log "Get root file name"
  RESPBIAN_IMG_NAME=`unzip -l ${RESPBIAN_FILENAME} | grep img | awk '{print $4}'`
  #extract zip archive
  log "Extract root image from file"
  unzip ${RESPBIAN_FILENAME} -d ${RESPBIAN_EXTRACT_DIR}
  #create mount dir for loop device
}

function mount_rasbian_image {
  if [ ! -z "${RESPBIAN_IMAGE_PRESET}" ]; then 
    RESPBIAN_IMG_NAME=${RESPBIAN_IMAGE_PRESET}
  fi
  mkdir -p ${RESPBIAN_MOUNT_DIR}
  #grep the offset for the second partition
  RASPBIAN_IMG_OFFSET=`${FDISK_CMD} -l ${RESPBIAN_IMG_NAME} | grep Linux | awk '{print $2}'`
  #Size of the Image in MB
  RASPBIAN_IMG_SIZE=`${STAT_CMD} --printf="%s" ${RESPBIAN_IMG_NAME} | awk '{printf "%d", $1/1024/1024}'`
  _RASPBIAN_DEVICE_NODE="loop0"

  if [ "$RASPBIAN_IMG_SIZE" -lt "$RESPBIAN_IMAGE_MIN_SIZE_MB" ]; then
    #Resize image
    log "Resizing image..."
    truncate -s +2G ${RESPBIAN_IMG_NAME}
  fi
  #TODO: Need to improve the lo device mgnt e.g. if loop0 is in use
  sudo losetup /dev/${_RASPBIAN_DEVICE_NODE} ${RESPBIAN_IMG_NAME}

  sudo bash -c "sed -e 's/\s*\([\+0-9a-zA-Z]*\).*/\1/' << EOF | fdisk /dev/${_RASPBIAN_DEVICE_NODE}
d 
2 # partition number 2
n # new partition
p # primary partition
2 # partition number 2
${RASPBIAN_IMG_OFFSET}
  # default value for end of partition 2
p # print the in-memory partition table
w # write the partition table
q # and we're done
EOF"
  sync
  sudo losetup -d /dev/${_RASPBIAN_DEVICE_NODE}
  
  #Remount specific 2nd partition
  log "Remounting image for resizing the filesystem"
  #sudo kpartx -v -a ${RESPBIAN_IMG_NAME}
  #sudo ln -s /dev/mapper/loop0p1 /dev/loop0p1
  #sudo ln -s /dev/mapper/loop0p2 /dev/loop0p2
  #sudo kpartx -v -d /dev/loop0
  #sudo rm /dev/loop0p1
  #sudo rm /dev/loop0p2
  sudo losetup -o $(($RASPBIAN_IMG_OFFSET*$BLOCK_SIZE)) /dev/${_RASPBIAN_DEVICE_NODE} ${RESPBIAN_IMG_NAME}
  sudo e2fsck -f /dev/${_RASPBIAN_DEVICE_NODE}
  sudo resize2fs /dev/${_RASPBIAN_DEVICE_NODE}
  sudo e2fsck -f /dev/${_RASPBIAN_DEVICE_NODE}
  #sudo e2fsck -f -y -v -C 0 /dev/loop0
  log "Unbind loop device from /dev/${_RASPBIAN_DEVICE_NODE}"
  sudo losetup -d /dev/${_RASPBIAN_DEVICE_NODE}
  
  #fi
  log "Binary offset [${RESPBIAN_IMG_NAME}]: ${RASPBIAN_IMG_OFFSET}"
  #calculate the correct byte offset
  RASPBIAN_IMG_OFFSET=$(($RASPBIAN_IMG_OFFSET * $BLOCK_SIZE))
  pushd ${RESPBIAN_EXTRACT_DIR}
  sudo mount -o loop,offset=${RASPBIAN_IMG_OFFSET} ${RESPBIAN_IMG_NAME} ${RESPBIAN_MOUNT_DIR}
  popd
}

function manage_ssh_keys {
  #call this function only with mounted RESPBIAN Image
  mkdir -p ${RESPBIAN_MOUNT_DIR}/home/pi/.ssh/
  pushd ${RESPBIAN_MOUNT_DIR}/home/pi/.ssh/
  echo "y\n" | ssh-keygen -b 4096 -q -t rsa -P '' -f id_rsa
  popd
  mkdir -p ${RESPBIAN_CONFIG_DIR}/
  cp ${RESPBIAN_MOUNT_DIR}/home/pi/.ssh/id_rsa.pub ${RESPBIAN_CONFIG_DIR}/${RESPBIAN_HOSTNAME}.pub
  log "Read ssh key"
  _PUB_KEY=$(<${RESPBIAN_CONFIG_DIR}/${RESPBIAN_HOSTNAME}.pub)
  if [ -z "${SKIP_ADD_GITLAB_KEY}" ]; then 
    log "Add ssh key to Gitlab"
    curl --data-urlencode "key=${_PUB_KEY}" --data-urlencode "title=${RESPBIAN_HOSTNAME}" https://${GITLAB_HOST}/api/v3/user/keys?private_token=${GITLAB_PRIVATE_TOKEN} --insecure
  fi
  log "Create controll keys"
  pushd ${RESPBIAN_CONFIG_DIR}
  echo "y\n" | ssh-keygen -b 4096 -q -t rsa -P '' -C pi@remote_control -f ${RESPBIAN_HOSTNAME}_control
  popd

  _CONTROL_PUB_KEY=$(<${RESPBIAN_CONFIG_DIR}/${RESPBIAN_HOSTNAME}_control.pub)
  REMOTE_CONTROL_AUTHORIZED_KEY=`grep "${_CONTROL_PUB_KEY}" ${RESPBIAN_MOUNT_DIR}/home/pi/.ssh/authorized_keys`
  if [ -z "${REMOTE_CONTROL_AUTHORIZED_KEY}" ]; then
    log "Write control key to authorized_keys file"
    echo "" >> ${RESPBIAN_MOUNT_DIR}/home/pi/.ssh/authorized_keys
    echo "${_CONTROL_PUB_KEY}" >> ${RESPBIAN_MOUNT_DIR}/home/pi/.ssh/authorized_keys
  fi

  log "Setup pubkey authN for SSH"
  #Enable Public key authentication, disable password authN
  MOD_RC_LOCAL=$(sed -e ':a;N;$!ba;s/#PubkeyAuthentication yes/PubkeyAuthentication yes/g' ${RESPBIAN_MOUNT_DIR}/etc/ssh/sshd_config)
  echo "${MOD_RC_LOCAL}" | sudo tee ${RESPBIAN_MOUNT_DIR}/etc/ssh/sshd_config $1>/dev/null
  MOD_RC_LOCAL=$(sed -e ':a;N;$!ba;s/#PasswordAuthentication yes/PasswordAuthentication no/g' ${RESPBIAN_MOUNT_DIR}/etc/ssh/sshd_config)
  echo "${MOD_RC_LOCAL}" | sudo tee ${RESPBIAN_MOUNT_DIR}/etc/ssh/sshd_config $1>/dev/null
  MOD_RC_LOCAL=$(sed -e ':a;N;$!ba;s/#AuthorizedKeysFile/AuthorizedKeysFile/g' ${RESPBIAN_MOUNT_DIR}/etc/ssh/sshd_config)
  echo "${MOD_RC_LOCAL}" | sudo tee ${RESPBIAN_MOUNT_DIR}/etc/ssh/sshd_config $1>/dev/null
}

function setup_openvpn_config {
  if [ ! -e "${OPENVPN_CA_FILE}" ]; then
    echo -e "\e[91mNo OPENVPN CA file at: ${OPENVPN_CA_FILE}\e[39m"
    return 1
  fi

  if [ ! -e "${OPENVPN_CERT_FILE}" ]; then
    echo -e "\e[91mNo OPENVPN CERT file at: ${OPENVPN_CERT_FILE}\e[39m"
    return 1
  fi

  if [ ! -e "${OPENVPN_KEY_FILE}" ]; then
    echo -e "\e[91mNo OPENVPN KEY file at: ${OPENVPN_KEY_FILE}\e[39m"
    return 1
  fi

  if [ ! -e "${OPENVPN_CONFIG_FILE}" ]; then
    echo -e "\e[91mNo OPENVPN CONFIG file at: ${OPENVPN_CONFIG_FILE}\e[39m"
    return 1
  fi

  sudo $CP ${OPENVPN_CONFIG_FILE} ${RESPBIAN_MOUNT_DIR}/etc/openvpn/{OPENVPN_SERVICE_NAME}.conf
  
  sudo $CP ${OPENVPN_KEY_FILE} ${RESPBIAN_MOUNT_DIR}/etc/openvpn/
  OPENVPN_KEY_FILE_NAME=`basename ${OPENVPN_KEY_FILE}`
  sed -i -E "s/^key\s.*/key ${OPENVPN_KEY_FILE_NAME}/" ${RESPBIAN_MOUNT_DIR}/etc/openvpn/{OPENVPN_SERVICE_NAME}.conf
  
  sudo $CP ${OPENVPN_CERT_FILE} ${RESPBIAN_MOUNT_DIR}/etc/openvpn/
  OPENVPN_CERT_FILE_NAME=`basename ${OPENVPN_CERT_FILE}`
  sed -i -E "s/^cert\s.*/cert ${OPENVPN_CERT_FILE_NAME}/" ${RESPBIAN_MOUNT_DIR}/etc/openvpn/{OPENVPN_SERVICE_NAME}.conf
  
  sudo $CP ${OPENVPN_CA_FILE} ${RESPBIAN_MOUNT_DIR}/etc/openvpn/
  OPENVPN_CA_FILE_NAME=`basename ${OPENVPN_CA_FILE}`
  sed -i -E "s/^ca\s.*/ca ${OPENVPN_CA_FILE_NAME}/" ${RESPBIAN_MOUNT_DIR}/etc/openvpn/{OPENVPN_SERVICE_NAME}.conf

  return 0
}

function copy_files_to_image {
  pushd ${RESPBIAN_MOUNT_DIR}/home/pi
  git clone https://github.com/travisfsmith/sweetsecurity
  git clone --recursive git://git.bro.org/bro
  popd
  #wait_for_newline 
  manage_ssh_keys
  setup_openvpn_config

  log "Creating rc.local boot scripts"
  sudo bash -c "cat > ${RESPBIAN_MOUNT_DIR}/etc/init_configuration.sh <<EOF
    #!/bin/bash -e
    
    exec 2> /tmp/init_configuration.log  # send stderr from rc.local to a log file
    exec 1>&2                      # send stdout to the same log file
    set -x                         # tell sh to display commands before execution
    
    #echo "'\$PWD'"
    #echo $PWD

    #mount -t proc none /proc #remove for production
    #dhclient -i eth0 #remove for production

    NEEDED_PACKAGES=( git openvpn python curl cmake g++ flex bison libpcap-dev libssl1.0-dev python-dev python-pip python-flask python-scapy apache2 libapache2-mod-wsgi swig nmap tcpdump ant zip oracle-java8-jdk )

    NEEDED_PYTHON_PACKAGES=( elasticsearch requests flask-mail flask_wtf cryptography )

    function check_install_package {
      PKG_OK="'\$'"(dpkg-query -W --showformat='"'\${Status}'"\n' "'\$1'" | grep \"install ok installed\")
      if [ \"\" == \""'\$PKG_OK'"\" ]; then
        apt-get --force-yes --yes install "'\$1'"
      fi
    }

    function check_python_install_package {
        pip install "'\$1'"
    }

    systemctl start ssh

    # if grep -q 'Versatile' /proc/cpuinfo; then
    #   DEVICE_NODE=\"sda\";
    #   DEVICE_PARTITION=\""'\${DEVICE_NODE}'"2\";
    # else
    #   DEVICE_NODE=\"mmcblk0\";
    #   DEVICE_PARTITION=\""'\${DEVICE_NODE}'"p2\";
    # fi

    # MAX_DEVICE_SPACE="'\$'"(cat /proc/partitions | grep \"\<"'\$'"{DEVICE_NODE}\>\" | awk '{printf \"%d\n\","'\$'"3 / 1024}')

    # e2fsck -f /dev/"'\${DEVICE_PARTITION}'"
    # parted /dev/"'\${DEVICE_NODE}'" --script resizepart 2 "'\${MAX_DEVICE_SPACE}'"
    # resize2fs /dev/"'\${DEVICE_PARTITION}'"

    apt update

    for pkg in \""'\${NEEDED_PACKAGES[@]}'"\"; do
      check_install_package "'\$pkg'"
    done
    

    for pkg in \""'\${NEEDED_PYTHON_PACKAGES[@]}'"\"; do
      check_python_install_package "'\$pkg'"
    done

    pushd /home/pi/bro
    ./configure
    make -j4
    make install
    popd

    pushd /home/pi/sweetsecurity
    echo "2" | python setup.py
    popd

    systemctl start openvpn@$OPENVPN_SERVICE_NAME.service

    exit 0
EOF"
  sudo chmod 755 ${RESPBIAN_MOUNT_DIR}/etc/init_configuration.sh
  RC_LOCAL_SCRIPT=`grep "init_configuration.sh" ${RESPBIAN_MOUNT_DIR}/etc/rc.local`
  log "Checking Raspbian /etc/rc.local"
  if [ -z "${RC_LOCAL_SCRIPT}" ]; then
    log "Editing Raspbian /etc/rc.local"
    MOD_RC_LOCAL=$(sed -e ':a;N;$!ba;s/\nexit 0/\nbash -c \/etc\/init_configuration.sh \&>\/dev\/null \&\nexit 0/g' ${RESPBIAN_MOUNT_DIR}/etc/rc.local)
    echo "${MOD_RC_LOCAL}" | sudo tee ${RESPBIAN_MOUNT_DIR}/etc/rc.local $1>/dev/null
  fi

  #sudo bash -c "sed -e ':a;N;\$!ba;s=\nexit 0=\nbash -e \/etc\/init_configuration.sh \& disown;\nexit 0=g' ${RESPBIAN_MOUNT_DIR}/etc/rc.local > ${RESPBIAN_MOUNT_DIR}/etc/rc.local1"
  

  if [[ $EMULATION -eq 1 ]]; then
    log "Copying /etc/resolv.conf for emulation to image"
    sudo cp /etc/resolv.conf ${RESPBIAN_MOUNT_DIR}/etc/resolv.conf
    sudo touch ${RESPBIAN_MOUNT_DIR}/ssh   # this enables ssh
  fi
}

function umount_rasbian_image {
  sudo umount ${RESPBIAN_MOUNT_DIR}
}

function flash_raspbian_image_to_sd {
  if [ -n "${RESPBIAN_FILENAME}" ]; then 
    while true; do 
      echo "sudo dd if=${RESPBIAN_IMG_NAME} of=${RASPBIAN_SD_CARD} bs=4M"
      read -r -p "Are You Sure? [Y/n] " input
       case $input in
         [yY][eE][sS]|[yY])
         echo "Yes"
         break
         ;;
         [nN][oO]|[nN])
         echo "Exitting"
         exit 1
         ;;
        *)
         echo "Invalid input..."
         ;;
      esac
    done
    echo "Running"
    echo "sudo dd if=${RESPBIAN_IMG_NAME} of=${RASPBIAN_SD_CARD} bs=4M"
    #test if vars exist and are set in the right way 
    sudo dd if=${RESPBIAN_IMG_NAME} of=${RASPBIAN_SD_CARD} bs=4M
  fi
}

function emulate_raspbian {
  #Respi Kernel @ https://github.com/dhruvvyas90/qemu-rpi-kernel/blob/master/kernel-qemu-4.4.34-jessie
  #https://ownyourbits.com/2017/02/06/raspbian-on-qemu-with-network-access/
  
  QEMU_BRIDGE=qemu-br0
  #find active network interface
  log "Find active network interface"
  QEMU_IFACE=`ip r l | grep default | awk '{print $5}'`
  #QEMU_IFACE="eth0"
  log "Set IP for $QEMU_IFACE"
  #sudo ip addr add dev $QEMU_IFACE 10.0.0.1
  [[ "$QEMU_IFACE" == "" ]] && { echo "No default route found"; return 1; }

  QEMU_MAC=00:50:a9:94:92:92
  PRESET_IP_FW=$( sysctl net.ipv4.ip_forward | cut -d= -f2 )

  log "Looking for IP from $QEMU_IFACE"
  IP=$( ip a | grep "global $QEMU_IFACE" | grep -oP '\d{1,3}(.\d{1,3}){3}' | head -1 )
  [[ "$IP" == "" ]] && { echo "No IP found for $QEMU_IFACE"; return 1; }
  
  type brctl &>/dev/null || { echo "bridge-utils is not installed"; return 1; }
  
  #modprobe tun &>/dev/null
  #grep -q tun <(lsmod) || { echo "Can not load tun module!"; return 1; }
  log "Creating /etc/qemu-ifup"
  sudo bash -c "cat > /etc/qemu-ifup <<EOF
  #!/bin/sh
  echo \"Executing /etc/qemu-ifup\"
  echo \"Bringing up "'\$1'" for bridged mode...\"
  sudo /sbin/ip link set "'\$1'" up promisc on
  echo \"Adding "'\$1'" to $QEMU_BRIDGE...\"
  sudo /sbin/brctl addif $QEMU_BRIDGE "'\$1'"
  sleep 2
EOF"
  
  log "Creating /etc/qemu-ifdown"
  sudo bash -c "cat > /etc/qemu-ifdown <<EOF
  #!/bin/sh
  echo \"Executing /etc/qemu-ifdown\"
  sudo /sbin/ip link set "'\$1'" down
  sudo /sbin/brctl delif $QEMU_BRIDGE "'\$1'"
  sudo /sbin/ip link delete dev "'\$1'"
EOF"
  
  log "Change mod qemu-ifup/down"
  sudo chmod 750 /etc/qemu-ifdown /etc/qemu-ifup
  sudo chown root:adm /etc/qemu-ifup /etc/qemu-ifdown

  QEMU_ROUTES=$( ip r | grep $QEMU_IFACE)
  QEMU_BRROUT=$( echo "$QEMU_ROUTES" | sed "s=$QEMU_IFACE=$QEMU_BRIDGE=" )
  sudo brctl addbr $QEMU_BRIDGE
  sudo brctl addif $QEMU_BRIDGE $QEMU_IFACE
  sudo ip l set up dev $QEMU_BRIDGE
  sudo ip r flush dev $QEMU_IFACE
  log "Set IP address for $QEMU_BRIDGE"
  sudo ip a a dev $QEMU_BRIDGE $IP
  log "Exchange rounting interface from $QEMU_IFACE to $QEMU_BRIDGE"
  echo "$QEMU_BRROUT" | tac | while read l; do sudo ip r a $l; done
  log "Adding tap interface"
  tap_precreation=$(ip tuntap list | cut -d: -f1 | sort)
  sudo ip tuntap add user $USER mode tap
  tap_postcreation=$(ip tuntap list | cut -d: -f1 | sort)

  [[ "$QEMU_MAC" == "" ]] && printf -v QEMU_MAC "52:54:%02x:%02x:%02x:%02x" $(( $RANDOM & 0xff)) $(( $RANDOM & 0xff )) $(( $RANDOM & 0xff)) $(( $RANDOM & 0xff ))

  QEMU_TAPIF=$(comm -13 <(echo "$tap_precreation") <(echo "$tap_postcreation"))
  QEMU_NET_ARGS="-net nic,macaddr=$QEMU_MAC -net tap,ifname=$QEMU_TAPIF,script=no,downscript=no"

  RESPBIAN_MOUNT_DIR_TEST="${RESPBIAN_MOUNT_DIR}_TEST"
  mkdir -p ${RESPBIAN_MOUNT_DIR_TEST}
  RESPBIAN_FILENAME_TEST=${RESPBIAN_IMG_NAME%.img}-test.img
  
  log "Copying test image ${RESPBIAN_FILENAME_TEST}"
  cp ${RESPBIAN_IMG_NAME} ${RESPBIAN_FILENAME_TEST}
  
  #log "Resize test image"
  #qemu-img resize ${RESPBIAN_FILENAME_TEST} +2G
  
  #mount the whole image in with gnome /root and /boot
  #gnome-disk-image-mounter respbian-image.img
  log "Mounting test image ${RESPBIAN_FILENAME_TEST}"
  sudo mount -o loop,offset=${RASPBIAN_IMG_OFFSET} ${RESPBIAN_FILENAME_TEST} ${RESPBIAN_MOUNT_DIR_TEST}
  
  log "Create udev rules ${RESPBIAN_MOUNT_DIR_TEST}/etc/udev/rules.d/90-qemu.rules"
  sudo bash -c 'cat > ${RESPBIAN_MOUNT_DIR_TEST}/etc/udev/rules.d/90-qemu.rules <<EOF
  KERNEL=="sda", SYMLINK+="mmcblk0"
  KERNEL=="sda?", SYMLINK+="mmcblk0p%n"
  KERNEL=="sda2", SYMLINK+="root"
EOF'
  QEMU_MAJOR=$( qemu-system-arm --version | grep -oP '\d+\.\d+\.\d+' | head -1 | cut -d. -f1 )
  QEMU_MINOR=$( qemu-system-arm --version | grep -oP '\d+\.\d+\.\d+' | head -1 | cut -d. -f2 )

  if [[ $QEMU_MAJOR == 2 ]] && [[ $QEMU_MINOR < 8 ]]; then
    log "Sed[${QEMU_MAJOR}:${QEMU_MINOR}] libarmmem ${RESPBIAN_MOUNT_DIR_TEST}/etc/ld.so.preload"
    sudo sed -i '/^[^#].*libarmmem.so/s/^\(.*\)$/#\1/' ${RESPBIAN_MOUNT_DIR_TEST}/etc/ld.so.preload;
  fi
  if [[ $QEMU_MAJOR <  2 ]]; then
    log "Sed[${QEMU_MAJOR}] libarmmem ${RESPBIAN_MOUNT_DIR_TEST}/etc/ld.so.preload"
    sudo sed -i '/^[^#].*libarmmem.so/s/^\(.*\)$/#\1/' ${RESPBIAN_MOUNT_DIR_TEST}/etc/ld.so.preload;
  fi
  log "Umount ${RESPBIAN_MOUNT_DIR_TEST}"
  sudo umount ${RESPBIAN_MOUNT_DIR_TEST}

  #QEMU_APPEND_OPIONTS="earlyprintk loglevel=8 console=ttyAMA0,115200 dwc_otg.lpm_enable=0"
  #QEMU_APPEND_ROOTSHELL="init=/bin/sh "
  log "Starting emulation"
  sudo /etc/qemu-ifup $QEMU_TAPIF
  qemu-system-arm -kernel kernel-qemu-4.4.34-jessie -cpu arm1176 -m 256 -M versatilepb $QEMU_NET_ARGS -no-reboot -serial stdio -append "root=/dev/sda2 panic=1 rootfstype=ext4 rw" -drive format=raw,file=${RESPBIAN_FILENAME_TEST} -monitor unix:/tmp/respbian-qemu-monitor,server,nowait
  
  #This emulation needs a newer version of qemu >=2.10
  #QEMU_NET_ARGS="-device e1000,id=e0,netdev=net0,nic,macaddr=$QEMU_MAC -netdev tap,ifname=$QEMU_TAPIF,script=no,downscript=no,id=net0"
  #${EMULATION_QEMU_BINARY} -M raspi2 $QEMU_NET_ARGS -append "rw earlyprintk loglevel=8 console=ttyAMA0,115200 dwc_otg.lpm_enable=0 root=/dev/mmcblk0p2 rootfstype=ext4" -cpu arm1176 -dtb bcm2709-rpi-2-b.dtb -sd ${RESPBIAN_FILENAME_TEST} -kernel kernel-test.img -m 1G -smp 4 -serial stdio -no-reboot -monitor unix:/tmp/respbian-qemu-monitor,server,nowait

  sudo /etc/qemu-ifdown $QEMU_TAPIF

  sudo ip l set down dev $QEMU_TAPIF 
  sudo ip tuntap del $QEMU_TAPIF mode tap
  sudo sysctl net.ipv4.ip_forward="$PRESET_IP_FW"
  sudo ip l set down dev $QEMU_BRIDGE
  sudo brctl delbr $QEMU_BRIDGE
  echo "$QEMU_ROUTES" | tac | while read l; do sudo ip r a $l; done
}

while getopts ":vsef:i:" opt; do
  case $opt in
    f ) 
      RESPBIAN_FILENAME_PRESET="$OPTARG"
      ;;
    \?) echo "Invalid option: -"$OPTARG"" >&2
      exit 1
      ;;
    i )
      INPUT_IMAGE=1
      log "Set previous donwloaded image"
      RESPBIAN_IMAGE_PRESET="$OPTARG"
      ;;
    e )
      EMULATION=1
      log "Enter emualation mode"
      ;;
    v )
      VERBOSE=1
      log "Verbose mode enabled"
      ;;
    s )
      SKIP_ADD_GITLAB_KEY=1
      log "Skip to add key to gitlab"
      ;;
    : ) 
      echo "Option -"$OPTARG" requires an argument." >&2
      exit 1
      ;;
  esac
done
if [[ $INPUT_IMAGE -ne 1 ]]; then
  download_rasbian_archive
  extract_rasbian_image
fi
mount_rasbian_image
copy_files_to_image
umount_rasbian_image

if [[ $EMULATION -eq 1 ]]; then
  emulate_raspbian
fi