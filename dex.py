# Tento kod je soucast diplomove prace "Vyuziti zranitelnosti Janus na operacnim systemu Android"
# Autor: Bc. Vit Soucek (soucevi1@fit.cvut.cz)


class Dex:
    """
    Class representing the DEX file
    that gets prepended to the APK.
    """

    def __init__(self, data):
        """
        An object of this class knows its
        data and their length.

        :param data: Data of the DEX file
        :type data: bytearray
        """
        self.data = data
        self.length = len(data)
