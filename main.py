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

    # Convert the text in the image to a string
    text = pytesseract.image_to_string(image=(DOWNLOADS / file_path).as_posix(), config='--psm 6')

    # Fix any errors in the binary string
    text = text.replace('€', 'e')
    text = text.replace('¢', 'c')
    text = text.replace('C', '')

    # Print the initial string
    print('[bold blue]Initial String[/]')
    print(f'[green]{text}[/]')

    # Match only words which contain only hex characters and are a minimun of 5 characters long
    hex_pattern = r'\b[0-9a-fA-F]{5,}\b'

    # Find all words which contain only hex characters
    hex_matches = re.findall(hex_pattern, text)

    # Discard any hex matches which start with 00
    hex_matches = [match for match in hex_matches if not match.startswith('00')]

    # Print the hex matches
    print()
    print('[bold blue]Hex Matches[/]')
    for match in hex_matches:
        print(f'[green]{match}[/]')

    # Join the hex matches into a single string
    hex_string = ''.join(hex_matches)

    # Print the hex string
    print()
    print('[bold blue]Hex String[/]')
    print(f'[green]{hex_string}[/]')

    # Print the length of the hex string
    print()
    print('[bold blue]Length of Hex String[/]')
    print(f'[green]{len(hex_string)}[/]')

    # Convert hex string to bytes
    bytes_from_string = bytes.fromhex(hex_string)

    # Convert the bytes to an ascii string
    ascii_string = bytes_from_string.decode('ascii')

    # Print the ascii string
    print()
    print('[bold blue]Decoded String[/]')
    print(f'[green]{ascii_string}[/]')

if __name__ == '__main__':
    root = tk.Tk()
    root.withdraw()

    main()
