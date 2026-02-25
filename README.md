# pscan
Pscan is a Network Scanner That detects packets and can log them to a pcap file and is made with a Network Filter
# Prerequisites
  * A Linux Device
  * Kernel Version >= 4.13
  * C Compiler (e,g) gcc , clang
  * Make
# Installation
  Clone the repository
  ~~~
    git clone https://github.com/yoyo95104/pscan.git 
    cd pscan
  ~~~
  Then make the Program
  ~~~
  make
  ~~~  
  And export the binary
  ~~~
  export $PATH=$PATH:your/dir/pscan
  ~~~
  # Notice
  You have to run this program with sudo or as root
  # Debugging 
  If the kernel module refused to unload , unload it like this
  ~~~
   bash sudo rmmod filter
  ~~~
  or Restart
