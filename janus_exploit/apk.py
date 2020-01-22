# Tento kod je soucast diplomove prace "Vyuziti zranitelnosti Janus na operacnim systemu Android"
# Autor: Bc. Vit Soucek (soucevi1@fit.cvut.cz)
#
# Pouzite zdroje:
#     - Specifikace formatu souboru PKZip:
#         autor: Florian Buchholz (buchhofp@jmu.edu)
#         dostupne z: https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
#         V komentarich v kodu referovana pouze jako "documentation".

import struct


class Apk:
    """
    Class representing an APK file.
    """

    def __init__(self, data):
        """
        The contained members are the data of the APK,
        PKZip signature constants (provided by the documentation),
        offset of the start of the 'Central Directory' section
        and offset of the 'End of the Central Directory' section.

        :param data: Data of the APK file
        :type data: bytearray
        """
        self.data = data
        self.FILE_HEADER_SIGNATURE = b'PK\x01\x02'
        self.END_OF_CENTRAL_DIRECTORY_SIGNATURE = b'PK\x05\x06'
        self.cd_end = self.get_central_directory_end()
        self.cd_start = self.get_central_directory_start()

    def get_central_directory_end(self):
        """
        Find the section 'End of the Central Directory'.
        Use the signature mentioned in the PKZip documentation
        (PK\x05\x06) to locate the offset.

        :return: Offset of the 'End of the central directory' section within the APK
        :rtype: long
        """
        return self.data.find(self.END_OF_CENTRAL_DIRECTORY_SIGNATURE)

    def get_central_directory_start(self):
        """
        Find the offset of the start of the central directory.
        According to the PKZip specification, the offset is always
        written in the 'End of the Central Directory' section on offset
        16 to 20.

        :return: Offset of the start of the central directory
        :rtype: long
        """
        return struct.unpack("<L", self.data[self.cd_end + 16:self.cd_end + 20])[0]

    def get_local_header(self, cd_file_header_offset):
        """
        Find the relative offset of local header. This is the offset
        of where to find the corresponding local file header from
        the start of the first disk.
        According to the documentation, the offset is located
        in each 'File Header' section of the Central Directory
        on offset 0x2A - 0x2D (42 - 46).

        :param cd_file_header_offset: Offset in the APK where to start looking for a new 'File Header' section
        :type cd_file_header_offset: long
        :return: Offset of the local header
        :rtype: long
        """
        return struct.unpack("<L", self.data[cd_file_header_offset + 42:cd_file_header_offset + 46])[0]

    def get_next_file_header(self, search_from, search_to):
        """
        Find the next File Header in the Central Directory.
        Search only within given range of offsets.

        :param search_from: Offset where to start searching
        :param search_to: Offset where to stop searching
        :return: Offset of the next File Header within the Central Directory
        :type search_from: long
        :type search_to: long
        :rtype: long
        """
        return self.data.find(self.FILE_HEADER_SIGNATURE, search_from, search_to)
