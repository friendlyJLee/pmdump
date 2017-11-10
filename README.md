# pmdump

Pmdump is a simple tool that provides process memory acquistion on Linux or Android.
Pmdump dumps process memory with its header information from /proc/<pid>/maps file. Data is dumped either to the file or throughout the network.
  
## Usage

### To use prebuilt binary

There are prebuilt pmdump binaries in /pmdump_prebuilt_bin folder. 
They can be used to dump a process memory.
To build, please refer to below the build isntruction.

pmdump_parser.py is useful script that parses the memory dump file.

### pmdump

pmdump is used to dump process memory. Running of pmdump may requrire root permission.

```bash
./pmdump [OPTION]... MODE[,MODE]... <pid>
./pmdump [OPTION]... MODE[,MODE]... <pid> <ip-address> <port>

Dumping process memory to 'output_pmdump.bin' file or network.
The dumped result contains /proc/<pid>/maps entries info and its memory contents.

Options
 --raw	Dumping only data without /proc/<pid>/maps info header
 --anon	Dumping only anonymous memory

Each MODE is of the form '[-+][rwxps]'. If no mode is given, don't care the permission

Example
 ./pmdump +r +w -x +p --anon 1928	# dump only 'rw-p' permission with no file-mapped memory.
 ./pmdump +w --raw 1928 127.0.0.1 1212	# dump only writable memory without header info.
 ```

### pmdump_parser.py

pmdump_parser is the script that parses the dump images created by pmdump.

```bash
Usage: pmdump_parser.py [--raw|-<number>] <pmdumped_file>

print maps information from the dump file if no option is given.

Option:
    --raw       export only data part without header information
    -number     export given entry number's memory region

Example:
    ./pmdump_parser.py output.bin           // show memory info like 'cat /proc/<pid>/maps
    ./pmdump_parser.py --raw output.bin     // output_raw.bin is generated
    ./pmdump_parser.py -10 output.bin       // output_10.bin is generated
```

## How to Build

### Android

```bash
cd pmdump_src
make -f Makefile.android (arm|x86|x86_64)
``` 

### Ubuntu

```bash
cd pmdump_src
make -f Makefile.host
```

## Example usages in Android

adb root previlage requires to run pmdump in Android

```bash
adb root
```

Copy pmdump to proper folder. /data folder is a good choice

```bash
adb push pmdump /data/pmdump
```

Find the processid of the process that you want to dump using DDMS or ps command

```bash
adb shell ps
```

Dump memory and copy it to the host

```bash
adb shell
$ cd data
$ ./pmdump +r +w -x +p <pid> 
$ exit
adb pull /data/output_pmdump.bin .
```

Or, dump memory and get it thoughout the network

```bash
# in remote PC
nc -lvvv 1212 > dumpfile.bin

# in PC connected with Android
adb shell
$ cd data
$ ./pmdump +r +w -x +p <pid> 192.168.1.154 1212
$ exit
```
