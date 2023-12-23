from ast import main
from logging import root
from pathlib import Path
import re

import tkinter as tk
from tkinter import filedialog

import pytesseract

from rich import print

DOWNLOADS = Path().home() / 'Downloads'

def main():
    # Open the file dialog
    file_path = filedialog.askopenfilename(initialdir=DOWNLOADS, title='Select a File')

    # Get the filename from the file path
    file_path = Path(file_path)

    # Check if the file exists
    if not file_path.exists():
        print('[bold red]File does not exist![/]')

        return

    binary = pytesseract.image_to_string(image=(DOWNLOADS / file_path).as_posix(), config='--psm 6')

    # Fix any errors in the binary string
    binary = binary.replace('€', 'e')
    binary = binary.replace('¢', 'c')
    binary = binary.replace('C', '')

    # Print the binary string
    print('[bold blue]Binary String[/]')
    print(f'[green]{binary}[/]')

    # Match only words which contain only hex characters and are a minimun of 2 characters long
    hex_pattern = r'\b[0-9a-f]{5,}\b'

    # Find all words which contain only hex characters
    hex_matches = re.findall(hex_pattern, binary)

    # Print the hex matches
    print()
    print('[bold blue]Hex Matches[/]')
    for match in hex_matches:
        print(f'[green]{match}[/]')

    # Convert hex characters to ascii
    ascii_string = ''.join(x for x in hex_matches)

    # Print the ascii string
    print()
    print('[bold blue]Ascii String[/]')
    print(f'[green]{ascii_string}[/]')

    # Print the length of the ascii string
    print()
    print('[bold blue]Length of Ascii String[/]')
    print(f'[green]{len(ascii_string)}[/]')

    # Convert ascii string to bytes
    bytes_string = bytes.fromhex(ascii_string)

    # Convert the bytes to an ascii string
    ascii_string = bytes_string.decode('ascii')

    # Print the ascii string
    print()
    print('[bold blue]Decoded String[/]')
    print(f'[green]{ascii_string}[/]')

if __name__ == '__main__':
    root = tk.Tk()
    root.withdraw()

    main()
