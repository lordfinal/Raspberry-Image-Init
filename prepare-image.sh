#!/bin/bash

RESPBIAN_FILENAME=respbian.zip
RESPBIAN_EXTRACT_DIR=./
RESPBIAN_CONFIG_DIR=${RESPBIAN_EXTRACT_DIR}config
RESPBIAN_IMG_NAME=''
RESPBIAN_MOUNT_DIR=./mounted
FDISK_CMD=/sbin/fdisk
BLOCK_SIZE=512
RASPBIAN_SD_CARD=''
RESPBIAN_HOSTNAME=bro-ids-first

function download_rasbian_archive {
  if [ -z "${RESPBIAN_FILENAME}" ]; then 
    #download archive
    wget https://downloads.raspberrypi.org/raspbian_lite_latest -O ${RESPBIAN_FILENAME}
  fi
}

function extract_rasbian_image {
  #get img filename
  RESPBIAN_IMG_NAME=`unzip -l ${RESPBIAN_FILENAME} | grep img | awk '{print $4}'`
  #extract zip archive
  unzip ${RESPBIAN_FILENAME} -d ${RESPBIAN_EXTRACT_DIR}
  #create mount dir for loop device
}

function mount_rasbian_image {
  mkdir -p ${RESPBIAN_MOUNT_DIR}
  #grep the offset for the second partition
  RASPBIAN_IMG_OFFSET=`${FDISK_CMD} -l ${RESPBIAN_IMG_NAME} | grep Linux | awk '{print $2}'`
  echo $RASPBIAN_IMG_OFFSET
  #calculate the correct byte offset
  RASPBIAN_IMG_OFFSET=$(($RASPBIAN_IMG_OFFSET * $BLOCK_SIZE))
  pushd ${RESPBIAN_EXTRACT_DIR}
  sudo mount -o loop,offset=${RASPBIAN_IMG_OFFSET} ${RESPBIAN_IMG_NAME} ${RESPBIAN_MOUNT_DIR}
  popd
}

function copy_files_to_image {
  pushd ${RESPBIAN_MOUNT_DIR}/home/pi
  git clone https://github.com/travisfsmith/sweetsecurity
  popd
  mkdir -p ${RESPBIAN_MOUNT_DIR}/home/pi/.ssh/
  pushd ${RESPBIAN_MOUNT_DIR}/home/pi/.ssh/
  echo "y\n" | ssh-keygen -b 4096 -q -t rsa -P '' -f id_rsa 
  popd
  mkdir -p
  cp ${RESPBIAN_MOUNT_DIR}/home/pi/.ssh/id_rsa.pub ${RESPBIAN_CONFIG_DIR}/bro-ids-first.pub
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
         exit 1
         ;;
      esac
    done
    sudo dd if=${RESPBIAN_IMG_NAME} of=${RASPBIAN_SD_CARD} bs=4M
  fi
}

while getopts ":f:" opt; do
  case $opt in
    f ) 
      RESPBIAN_FILENAME="$OPTARG"
      ;;
    \?) echo "Invalid option: -"$OPTARG"" >&2
      exit 1
      ;;
    : ) 
      echo "Option -"$OPTARG" requires an argument." >&2
      exit 1
      ;;
  esac
done

download_rasbian_archive
extract_rasbian_image
mount_rasbian_image
copy_files_to_image
umount_rasbian_image