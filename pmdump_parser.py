'''
pmdump_parser

It gives information from the dumped memory using pmdump.
It prints memory map information from the dump like 'cat /proc/<pid>/maps.
It also provides the function that export specific memory region.

@auther: Jaeho Lee
'''
import struct
import sys
import os


def printUsage():
    s = '''
    
Usage: pmdump_parser.py [--raw|-<number>] <pmdumped_file>

print maps information from the dump file if no option is given.

Option:
    --raw       export only data part without header information
    -number     export given entry number's memory region

Example:
    ./pmdump_parser.py output.bin           // show memory info like 'cat /proc/<pid>/maps
    ./pmdump_parser.py --raw output.bin     // output_raw.bin is generated
    ./pmdump_parser.py -10 output.bin       // output_10.bin is generated
    '''
    print s


MAGIC_HEADER_STRING = "PMDUMP_FILE_WITH_HEADER"
MAGIC_HEADER_STRING_LENGTH = 23
MEMORY_ENTRY_SIZE_IN_FILE = (4+4+4+5+4+13+4+1024)


def isPmdumpFile(pmFile):
    fp = open(pmFile, "rb")
    magic_str = fp.read(MAGIC_HEADER_STRING_LENGTH)
    fp.close()
    return magic_str == MAGIC_HEADER_STRING

def print_pmdump_info(pmFile):
    if isPmdumpFile(pmFile) == False:
        print "This file doesn't contain header information. "
        return

    fp = open(pmFile, "rb")
    fp.read(MAGIC_HEADER_STRING_LENGTH)

    # entry_numbers , body_offset
    entry_numbers, body_offset = struct.unpack("<II", fp.read(8))


    # define MEMORY_ENTRY_SIZE_IN_FILE (4+4+4+5+4+13+4+1024)
    for i in range(entry_numbers):
        entryBytes = fp.read(MEMORY_ENTRY_SIZE_IN_FILE)
        assert len(entryBytes) == MEMORY_ENTRY_SIZE_IN_FILE

        start_address, end_address, length, perm, offset, device, inode, filename = struct.unpack("<III5sI13si1024s", entryBytes)
        perm = perm[:5]
        device = device.split('\x00')[0]
        filename = filename.split('\x00')[0]

        print "[%5d] %lx-%lx %s%8lx%13s%6u\t%s" % (
               i, start_address, end_address, perm, offset, device, inode, filename)

    assert MAGIC_HEADER_STRING == fp.read(MAGIC_HEADER_STRING_LENGTH)
    assert fp.tell() == body_offset

    print " * entry_numbers: %d" % entry_numbers
    print " * body_offset in file: %x" % body_offset

    fp.close()


def export_raw_data(pmFile, target_entry_number = -1):
    if isPmdumpFile(pmFile) == False:
        print "This file doesn't contain header information. "
        return

    fp = open(pmFile, "rb+")
    fp.read(MAGIC_HEADER_STRING_LENGTH)

    # entry_numbers , body_offset
    entry_numbers, body_offset = struct.unpack("<II", fp.read(8))

    if target_entry_number == -1:
        start_offset = body_offset
        raw_data_length = os.path.getsize(pmFile) - start_offset
        output_file_name = pmFile + ".raw.bin"
        print "# Dumping all raw memory to %s. size: %d" % (output_file_name, raw_data_length)

    else:
        if target_entry_number < -1 or target_entry_number >= entry_numbers:
            print "Entry number is too big. It should be between %d and %d" % (0, entry_numbers-1)
            return

        # define MEMORY_ENTRY_SIZE_IN_FILE (4+4+4+5+4+13+4+1024)
        start_offset = body_offset
        for i in range(entry_numbers):
            entryBytes = fp.read(MEMORY_ENTRY_SIZE_IN_FILE)
            assert len(entryBytes) == MEMORY_ENTRY_SIZE_IN_FILE

            start_address, end_address, length, perm, offset, device, inode, filename = struct.unpack("<III5sI13si1024s", entryBytes)
            perm = perm[:5]
            device = device.split('\x00')[0]
            filename = filename.split('\x00')[0]

            if i == target_entry_number:
                raw_data_length = length
                print "[%5d] %lx-%lx %s%8lx%13s%6u\t%s" % (
                       i, start_address, end_address, perm, offset, device, inode, filename)
                output_file_name = pmFile + (".raw_entry_%d.bin" % target_entry_number)
                print "# Dumping entry %d memory region to %s. size: %d" % (target_entry_number, output_file_name, raw_data_length)
                break

            start_offset += length

    # dump file
    fp.seek(start_offset)

    dstFp = file(output_file_name, "wb")
    data = fp.read(raw_data_length)
    assert len(data) == raw_data_length

    dstFp.write(data)

    dstFp.close()
    fp.close()

    print " * Done"


def fileOffsetToEntryInfo(pmFile, target_offset):
    '''
    return given offset's memory map entry

    :param pmFile: dump file
    :param target_offset: file offset to retrieve mem entry info
    :return: Info string
    '''

    if isPmdumpFile(pmFile) == False:
        print "This file doesn't contain header information. "
        return

    fp = open(pmFile, "rb+")
    fp.read(MAGIC_HEADER_STRING_LENGTH)

    # entry_numbers , body_offset
    entry_numbers, body_offset = struct.unpack("<II", fp.read(8))


    if target_offset < body_offset or target_offset >= os.path.getsize(pmFile):
        print "[WARN] incorrect offset: %d" % target_offset
        fp.close()
        return None

    # define MEMORY_ENTRY_SIZE_IN_FILE (4+4+4+5+4+13+4+1024)
    start_offset = body_offset
    for i in range(entry_numbers):
        entryBytes = fp.read(MEMORY_ENTRY_SIZE_IN_FILE)
        assert len(entryBytes) == MEMORY_ENTRY_SIZE_IN_FILE

        start_address, end_address, length, perm, offset, device, inode, filename = struct.unpack("<III5sI13si1024s", entryBytes)
        perm = perm[:5]
        device = device.split('\x00')[0]
        filename = filename.split('\x00')[0]

        if target_offset >= start_offset and target_offset < start_offset + length:
            # FIND
            offset_in_region = target_offset - start_offset
            fp.close()
            return "[%d] %lx-%lx %s %lx %s %u %s (Found offset: 0x%x)" % (
                   i, start_address, end_address, perm, offset, device, inode, filename, offset_in_region)

        start_offset += length

    fp.close()
    return None


if __name__ == "__main__":


    mode = "SHOW_MODE"
    export_entry = -1
    inputFile = ''
    if len(sys.argv) == 3:
        inputFile = sys.argv[2]
        if sys.argv[1] == '--raw': mode = "RAW_EXPORT_MODE"
        elif sys.argv[1][0] == '-':
            mode = "ENTRY_EXPORT_MODE"
            export_entry = int(sys.argv[1][1:])
        else:
            print "Incorrect option : %s" % sys.argv[1]
            printUsage()
            sys.exit(-2)

    elif len(sys.argv) == 2:
        inputFile = sys.argv[1]
    else:
        printUsage()
        sys.exit(-2)

    if os.path.exists(inputFile) == False:
        print "No such a input file: %s" % inputFile
        printUsage()
        sys.exit(-2)


    print "# pmdump_parser running"
    print "  * mode: %s" % mode
    print "  * input: %s" % inputFile


    if mode == "SHOW_MODE":
        print_pmdump_info(inputFile)
    elif mode == "RAW_EXPORT_MODE":
        export_raw_data(inputFile)
    elif mode == "ENTRY_EXPORT_MODE":
        export_raw_data(inputFile, export_entry)



#### TEST
'''
for i in {0..782..1};
do
python pmdump_parser.py -$i output_pmdump_old.bin
cat output_pmdump_old.bin.raw_entry_$i.bin >> test_pmdump.bin
rm -f output_pmdump_old.bin.raw_entry_$i.bin
done
'''