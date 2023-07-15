# crack14gui.py

import os
import tkinter as tk
from tkinter import filedialog, messagebox
import binascii
import platform
import pefile
import lief
from capstone import *
from keystone import *
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64
import struct
import shutil

def identify_oep(file_path, oep_entry):
    try:
        pe = pefile.PE(file_path)
        oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        pe.close()

        # Update the entry field with the calculated OEP
        oep_entry.delete(0, tk.END)
        oep_entry.insert(tk.END, hex(oep))
    except Exception as e:
        # Handle any exceptions or error cases
        oep_entry.delete(0, tk.END)
        oep_entry.insert(tk.END, "Error: " + str(e))

def dump_unpacked_executable(file_path):
    # This is highly dependent on the specific packer/protector used and might involve
    # complex operations like process injection, debugging, etc. More details needed for full implementation.
    pass

def identify_import_table_rva(file_path, import_table_rva_entry):
    try:
        pe = pefile.PE(file_path)
        import_table_rva = pe.get_section_by_rva(pe.DIRECTORY_ENTRY_IMPORT.struct.VirtualAddress).PointerToRawData
        pe.close()

        # Update the entry field with the calculated import table RVA
        import_table_rva_entry.delete(0, tk.END)
        import_table_rva_entry.insert(tk.END, hex(import_table_rva))
    except Exception as e:
        # Handle any exceptions or error cases
        import_table_rva_entry.delete(0, tk.END)
        import_table_rva_entry.insert(tk.END, "Error: " + str(e))

def fix_dump(file_path):
    # This function is meant to mimic the "Fix Dump" function in ImpREC.
    # The full implementation would depend on the specific nature of the fix needed.
    # This might involve rebuilding the import table, fixing the base address of the binary, etc.
    # More details would be needed for a full implementation.
    pass


def identify_entry_point(binary, root):
    try:
        pe = pefile.PE(binary)
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        result_entry = tk.Entry(root)
        result_entry.grid(row=0, column=11)
        result_entry.insert(0, hex(entry_point))
    except pefile.PEFormatError:
        messagebox.showerror("Error", "Invalid PE file.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def locate_unpacking_stub(binary, root):
    try:
        pe = pefile.PE(binary)
        if hasattr(pe, "RICH_HEADER"):
            rich_header = pe.RICH_HEADER
            unpacking_stub_offset = rich_header.clear_data_start_offset
            result_entry = tk.Entry(root)
            result_entry.grid(row=1, column=11)
            result_entry.insert(0, hex(unpacking_stub_offset))
        else:
            messagebox.showwarning("Warning", "No RICH header found.")
    except pefile.PEFormatError:
        messagebox.showerror("Error", "Invalid PE file.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def identify_import_table(binary, root):
    try:
        pe = pefile.PE(binary)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            import_table = pe.DIRECTORY_ENTRY_IMPORT
            import_table_entries = []
            for entry in import_table:
                dll_name = entry.dll.decode("utf-8")
                import_table_entries.append(dll_name)
            result_entry = tk.Entry(root)
            result_entry.grid(row=2, column=11)
            result_entry.insert(0, ", ".join(import_table_entries))
        else:
            messagebox.showwarning("Warning", "No import table found.")
    except pefile.PEFormatError:
        messagebox.showerror("Error", "Invalid PE file.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def identify_import_descriptor(binary, root):
    try:
        pe = pefile.PE(binary)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            import_table = pe.DIRECTORY_ENTRY_IMPORT
            import_descriptor_entries = []
            for entry in import_table:
                for imp in entry.imports:
                    import_descriptor_entries.append(imp.name.decode("utf-8"))
            result_entry = tk.Entry(root)
            result_entry.grid(row=3, column=11)
            result_entry.insert(0, ", ".join(import_descriptor_entries))
        else:
            messagebox.showwarning("Warning", "No import table found.")
    except pefile.PEFormatError:
        messagebox.showerror("Error", "Invalid PE file.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def identify_first_thunk(binary, root):
    try:
        pe = pefile.PE(binary)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            import_table = pe.DIRECTORY_ENTRY_IMPORT
            first_thunk_entries = []
            for entry in import_table:
                for imp in entry.imports:
                    first_thunk_entries.append(hex(imp.thunk))
            result_entry = tk.Entry(root)
            result_entry.grid(row=4, column=11)
            result_entry.insert(0, ", ".join(first_thunk_entries))
        else:
            messagebox.showwarning("Warning", "No import table found.")
    except pefile.PEFormatError:
        messagebox.showerror("Error", "Invalid PE file.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def identify_original_first_thunk(binary, root):
    try:
        pe = pefile.PE(binary)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            import_table = pe.DIRECTORY_ENTRY_IMPORT
            original_first_thunk_entries = []
            for entry in import_table:
                for imp in entry.imports:
                    original_first_thunk_entries.append(hex(imp.original_first_thunk))
            result_entry = tk.Entry(root)
            result_entry.grid(row=5, column=11)
            result_entry.insert(0, ", ".join(original_first_thunk_entries))
        else:
            messagebox.showwarning("Warning", "No import table found.")
    except pefile.PEFormatError:
        messagebox.showerror("Error", "Invalid PE file.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def modify_unpacking_stub(binary, root):
    try:
        pe = pefile.PE(binary)
        if hasattr(pe, "RICH_HEADER"):
            rich_header = pe.RICH_HEADER
            unpacking_stub_offset = rich_header.clear_data_start_offset
            # Modify the unpacking stub at the specified offset
            # Example: Modify the first byte to 0x90 (NOP instruction)
            with open(binary, "r+b") as file:
                file.seek(unpacking_stub_offset)
                file.write(bytes([0x90]))
            messagebox.showinfo(
                "Modification Successful", "Unpacking stub modified successfully."
            )
        else:
            messagebox.showwarning("Warning", "No RICH header found.")
    except pefile.PEFormatError:
        messagebox.showerror("Error", "Invalid PE file.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def restore_iat(binary, root):
    try:
        pe = pefile.PE(binary)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            import_table = pe.DIRECTORY_ENTRY_IMPORT
            for entry in import_table:
                for imp in entry.imports:
                    imp.thunk = imp.original_first_thunk
            pe.write(binary)
            messagebox.showinfo(
                "IAT Restoration Successful",
                "Import Address Table (IAT) restored successfully.",
            )
        else:
            messagebox.showwarning("Warning", "No import table found.")
    except pefile.PEFormatError:
        messagebox.showerror("Error", "Invalid PE file.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def unpack_binary(file_path, root):

    if not os.path.isfile(file_path):
        messagebox.showerror("Error", "The specified file does not exist.")
        return

    root.withdraw()  # Hide the main window
    export_folder = filedialog.askdirectory(
        title="Select folder"
    )  # Open the file dialog
    root.deiconify()  # Show the main window again

    if not os.path.isdir(export_folder):
        messagebox.showerror("Error", "The specified export folder does not exist.")
        return

    # Open the binary file
    pe = pefile.PE(file_path)

    # Identify the entry point
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # Locate and identify the unpacking stub
    # This part highly depends on the specific binary file you are dealing with.

    # Identify the Import Address Table (IAT)
    iat = pe.DIRECTORY_ENTRY_IMPORT

    # Identify the three parts of the Import Table Address:
    # IMAGE_IMPORT_DESCRIPTOR, the First Thunk, and the Original First Thunk.
    # This part highly depends on the specific binary file you are dealing with.

    # Modify the unpacking stub
    # This part highly depends on the specific binary file you are dealing with.

    # Restore the IAT
    # This part highly depends on the specific binary file you are dealing with.

    # Construct the path to the unpacked file (depends on your unpacking process)
    unpacked_file_name = (
        os.path.splitext(os.path.basename(file_path))[0]
        + "_unpacked"
        + os.path.splitext(file_path)[1]
    )
    unpacked_file_path = os.path.join(os.path.dirname(file_path), unpacked_file_name)

    # Copy the unpacked file to the export_folder
    shutil.copy2(unpacked_file_path, export_folder)

    print("Binary unpacked successfully.")


def calculate_rva(file_path, entry):
    try:
        pe = pefile.PE(file_path)
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        rva = entry_point - pe.OPTIONAL_HEADER.ImageBase
    except Exception as e:
        rva = str(e)

    entry.delete(0, tk.END)
    entry.insert(0, rva)


def calculate_iat(file_path, entry):
    try:
        pe = pefile.PE(file_path)
        iat_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]
        ].VirtualAddress
        iat_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]
        ].Size
    except Exception as e:
        iat_rva = str(e)
        iat_size = str(e)

    entry.delete(0, tk.END)
    entry.insert(0, f"RVA: {iat_rva}, Size: {iat_size}")


def calculate_ita(file_path, entry):
    try:
        pe = pefile.PE(file_path)
        ita_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ].VirtualAddress
        ita_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ].Size
    except Exception as e:
        ita_rva = str(e)
        ita_size = str(e)

    entry.delete(0, tk.END)
    entry.insert(0, f"RVA: {ita_rva}, Size: {ita_size}")


def calculate_import_table(file_path, entry):
    try:
        pe = pefile.PE(file_path)
        import_table = [entry.dll for entry in pe.DIRECTORY_ENTRY_IMPORT]
    except Exception as e:
        import_table = str(e)

    entry.delete(0, tk.END)
    entry.insert(0, ", ".join(import_table))


def search_string_in_binary(
    file_path, string_to_search, bad_boy_offset_entry, output_text
):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Search for the string as UTF-8 and UTF-16 encoded bytes
        string_to_search_bytes_utf8 = bytes(string_to_search, "utf-8")
        string_to_search_bytes_utf16 = string_to_search.encode("utf-16")[
            2:
        ]  # Ignore BOM

        for encoding, string_to_search_bytes in [
            ("utf-8", string_to_search_bytes_utf8),
            ("utf-16", string_to_search_bytes_utf16),
        ]:
            start_index = 0
            found_indices = []
            while start_index < len(data):
                index = data.find(string_to_search_bytes, start_index)
                if index != -1:
                    found_indices.append(hex(index))
                    start_index = index + 1
                else:
                    break

            output_text.insert(
                tk.END, f"Search results for '{string_to_search}' in {encoding}:\n"
            )
            if found_indices:
                for offset_str in found_indices:
                    offset = int(offset_str, 16)
                    end_of_string = data.find(
                        b"\x00\x00" if encoding == "utf-16" else b"\x00", offset
                    )  # Search for null terminator starting from offset
                    string_contents = data[offset:end_of_string].decode(
                        encoding, errors="replace"
                    )
                    output_text.insert(tk.END, f"Found at offset: ", "decimal")
                    output_text.insert(tk.END, f"{offset_str}\n", "hex")
                    output_text.insert(tk.END, f"String Contents: {string_contents}\n")

                    bad_boy_offset_entry.delete(0, tk.END)
                    bad_boy_offset_entry.insert(
                        0, offset_str
                    )  # Set Badboy offset to the found offset

                    # Determine the start offset of the code section
                    code_section_start_offset = get_code_section_start_offset(file_path)

                    # Find the first conditional jump instruction before the "Bad Boy" string
                    jmp_offset = find_conditional_jump_offset(
                        data, offset, code_section_start_offset
                    )
                    if jmp_offset is not None:
                        output_text.insert(
                            tk.END, f"Found conditional jump at offset: ", "decimal"
                        )
                        output_text.insert(tk.END, f"{hex(jmp_offset)}\n", "hex")

            else:
                output_text.insert(tk.END, "String not found.\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error: {str(e)}\n")


def get_code_section_start_offset(file_path):
    if platform.system() == "Windows":
        pe = pefile.PE(file_path)
        return pe.sections[0].VirtualAddress
    elif platform.system() == "Darwin":
        binary = lief.parse(file_path)
        return binary.segments[0].virtual_address
    else:
        raise NotImplementedError("Unsupported operating system.")


def find_conditional_jump_offset(data, string_offset, code_section_start_offset):
    cs = Cs(CS_ARCH_X86, CS_MODE_32)  # Use CS_MODE_64 for 64-bit binaries
    cs.detail = True  # Include instruction details
    jmp_instructions = [
        "je",
        "jne",
        "jz",
        "jnz",
        "jg",
        "jge",
        "jl",
        "jle",
        "ja",
        "jae",
        "jb",
        "jbe",
        "jmp",
    ]

    # Starting from the offset of "Bad Boy" and going backward until the start of the code section
    for i in range(string_offset, code_section_start_offset, -1):
        # We need to disassemble in blocks as Capstone may need more bytes to accurately disassemble an instruction
        # 15 is the maximum length of an x86/x86_64 instruction
        instruction_bytes = data[i - 15 : i]
        instructions = list(cs.disasm(instruction_bytes, i - 15))

        if instructions:
            last_instruction = instructions[-1]
            if last_instruction.mnemonic in jmp_instructions:
                return last_instruction.address

    return None


def patch_binary(file_path, offset, new_instruction, offset_base, arch_mode, root):
    # Determine architecture mode for Keystone
    if arch_mode == "32-bit":
        mode = KS_MODE_32
    elif arch_mode == "64-bit":
        mode = KS_MODE_64
    else:
        raise ValueError("Invalid architecture mode")

    # Convert offset to integer based on base
    offset = int(offset, offset_base)

    print(
        f"Offset: {offset}, New instruction: {new_instruction}, Arch mode: {arch_mode}"
    )

    try:
        # Use Keystone to assemble new_instruction into machine code
        ks = Ks(KS_ARCH_X86, mode)
        encoding, _ = ks.asm(new_instruction)
        new_instruction_machine_code = bytes(encoding)

        print(f"Machine code: {new_instruction_machine_code}")

        with open(file_path, "rb") as f:
            data = bytearray(f.read())

        # Replace the instruction at the specified offset with new_instruction_machine_code
        for i, byte in enumerate(new_instruction_machine_code):
            data[offset + i] = byte

        with open(file_path, "wb") as f:
            f.write(data)

        messagebox.showinfo("Success", "File patched successfully.")
    except Exception as e:
        messagebox.showerror(
            "Error", str(e), parent=root
        )  # Pass root as parent to the messagebox


def browse_files(file_path_entry):
    try:
        file_path_entry.delete(0, tk.END)  # Remove current file path
        file_path = filedialog.askopenfilename(
            filetypes=[("Executable Files", "*.exe"), ("App Files", "*.app")]
        )  # Open file dialog
        file_path_entry.insert(0, file_path)  # Insert new file path

        # Get the file extension
        _, file_extension = os.path.splitext(file_path)

        if file_extension == ".exe":
            # Parse the binary file using pefile
            pe = pefile.PE(file_path)
            # Search for all instances of the string "Bad boy"
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if entry.name is not None and entry.name.string == "Bad boy":
                    print(
                        f"Found 'Bad boy' at offset: {entry.directory.entries[0].data.struct.OffsetToData}"
                    )
        elif file_extension == ".app":
            # Extract the executable file path from the .app file
            app_name = os.path.splitext(os.path.basename(file_path))[0]
            executable_path = os.path.join(file_path, "Contents", "MacOS", app_name)
            file_path_entry.delete(0, tk.END)
            file_path_entry.insert(
                0, executable_path
            )  # Update file_path_entry with executable_path

            # Parse the binary file using lief
            binary = lief.parse(executable_path)
            # Search for all instances of the string "Bad boy"
            for section in binary.sections:
                if "Bad boy" in section.content:
                    print(f"Found 'Bad boy' in section: {section.name}")
        else:
            print("Unsupported file type.")
    except Exception as e:
        print("An error occurred: ", str(e))


def read_instruction(
    file_path,
    offset,
    instruction,
    bin_entry,
    hex_entry,
    dec_entry,
    offset_base,
    arch_mode,
):
    try:
        # Open the file in binary read mode
        with open(file_path, "rb") as f:
            # Convert the offset to an integer using the specified base
            offset = int(offset, offset_base)
            # Seek to the position in the file specified by the offset
            f.seek(offset)
            # Read the bytes at the current position
            bytes = f.read(
                16
            )  # The number of bytes to read can be adjusted based on your needs
    except FileNotFoundError:
        messagebox.showerror("Error", "File not found.")
        return
    except ValueError:
        messagebox.showerror("Error", "Invalid offset.")
        return
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return

    # Use the Capstone disassembler to disassemble the bytes
    if arch_mode == "32-bit":
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch_mode == "64-bit":
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        messagebox.showerror("Error", "Invalid architecture mode.")
        return

    # Disassemble the bytes
    for i in md.disasm(bytes, 0x1000):
        # Update the instruction Entry widget
        instruction.delete(0, tk.END)
        instruction.insert(0, f"{i.mnemonic} {i.op_str}")

        # Convert each byte to binary, decimal, and hexadecimal, then join them with spaces
        binary = " ".join(f"{byte:08b}" for byte in bytes)
        decimal = " ".join(str(byte) for byte in bytes)
        hexadecimal = " ".join(f"{byte:02x}" for byte in bytes)

        # Update the binary, hexadecimal, and decimal Entry widgets
        bin_entry.delete(0, tk.END)
        bin_entry.insert(0, binary)

        hex_entry.delete(0, tk.END)
        hex_entry.insert(0, hexadecimal)

        dec_entry.delete(0, tk.END)
        dec_entry.insert(0, decimal)
        break
    else:
        messagebox.showerror("Error", "Unable to disassemble instruction.")


def calculate_offset(
    base_virt_addr_entry, base_file_offset_entry, instr_virt_addr_entry
):
    try:
        # Get values from the entry fields
        base_virt_addr = base_virt_addr_entry.get().strip()
        base_file_offset = base_file_offset_entry.get().strip()

        # Check if the fields are empty
        if not base_virt_addr or not base_file_offset:
            raise ValueError(
                "Base Virtual Address and Base File Offset fields must be filled in"
            )

        # Convert inputs to integers
        base_virt_addr = int(base_virt_addr, 16)
        base_file_offset = int(base_file_offset, 16)

        # Calculate offset within section and file offset
        instr_virt_addr = base_virt_addr + base_file_offset

        instr_virt_addr_entry.delete(0, tk.END)
        instr_virt_addr_entry.insert(tk.END, hex(instr_virt_addr))

    except Exception as e:
        messagebox.showerror("Error", str(e))


def calculate_base_va(file_path, base_va_entry):
    try:
        pe = pefile.PE(file_path)
        base_va = pe.OPTIONAL_HEADER.ImageBase
        pe.close()

        # Update the entry field with the calculated base virtual address
        base_va_entry.delete(0, tk.END)
        base_va_entry.insert(tk.END, hex(base_va))
    except Exception as e:
        # Handle any exceptions or error cases
        base_va_entry.delete(0, tk.END)
        base_va_entry.insert(tk.END, "Error: " + str(e))


def calculate_base_offset(file_path, base_offset_entry):
    try:
        pe = pefile.PE(file_path)
        section = pe.sections[0]  # Assuming you want the first section's offset
        base_offset = section.PointerToRawData
        pe.close()

        # Update the entry field with the calculated base file offset
        base_offset_entry.delete(0, tk.END)
        base_offset_entry.insert(tk.END, hex(base_offset))
    except Exception as e:
        # Handle any exceptions or error cases
        base_offset_entry.delete(0, tk.END)
        base_offset_entry.insert(tk.END, "Error: " + str(e))


def open_offset_calculator(file_path):
    new_window = tk.Toplevel()
    new_window.title("Offset Calculator")

    # Set the size of the offset calculator window
    new_window.geometry("1300x300")

    tk.Label(
        new_window,
        text="Base Virtual Address: The starting memory address of the section where the instruction resides. You can find this in the section headers in Ghidra.",
    ).grid(row=0, column=0, columnspan=2)

    tk.Label(
        new_window,
        text="Base File Offset: The starting file offset of the section. You can find this in the section headers in Ghidra.",
    ).grid(row=1, column=0, columnspan=2)

    tk.Label(
        new_window,
        text="Instruction Virtual Address: The memory address of the instruction you want to patch. You found this when you identified the instruction in Ghidra.",
    ).grid(row=2, column=0, columnspan=2)

    base_virt_addr = tk.Entry(new_window)
    base_file_offset = tk.Entry(new_window)
    instr_virt_addr = tk.Entry(new_window)

    base_virt_addr.grid(row=0, column=2)
    base_file_offset.grid(row=1, column=2)
    instr_virt_addr.grid(row=2, column=2)

    tk.Button(
        new_window,
        text="Calculate",
        command=lambda: calculate_offset(
            base_virt_addr, base_file_offset, instr_virt_addr
        ),
    ).grid(row=3, column=0, columnspan=2)

    tk.Button(
        new_window,
        text="Calculate",
        command=lambda: calculate_offset(
            base_virt_addr, base_file_offset, instr_virt_addr
        ),
    ).grid(row=3, column=0, columnspan=2)

    tk.Button(
        new_window,
        text="Find Base Virtual Address",
        command=lambda: calculate_base_va(file_path.get(), base_virt_addr),
    ).grid(row=0, column=3)

    tk.Button(
        new_window,
        text="Find Base File Offset",
        command=lambda: calculate_base_offset(file_path.get(), base_file_offset),
    ).grid(row=1, column=3)

    new_window.mainloop()


def convert_value(value, from_base, to_base, output_entry):
    try:
        # Extract base values from the strings
        from_base = int(from_base.split(" - ")[0])
        to_base = int(to_base.split(" - ")[0])

        # Convert the value
        converted_value = int(value, from_base)

        # Format the converted value based on the to_base
        if to_base == 2:
            formatted_value = bin(converted_value)
        elif to_base == 10:
            formatted_value = str(converted_value)
        elif to_base == 16:
            formatted_value = hex(converted_value)

        # Update the output_entry with the converted value
        output_entry.delete(0, tk.END)
        output_entry.insert(0, formatted_value)
    except Exception as e:
        messagebox.showerror("Error", str(e))


def open_conversion_tool():
    new_window = tk.Toplevel()
    new_window.title("Conversion Tool")

    tk.Label(new_window, text="Value: The value you want to convert.").grid(
        row=0, column=0
    )
    tk.Label(new_window, text="From: The base of the value you want to convert.").grid(
        row=1, column=0
    )
    tk.Label(new_window, text="To: The base you want to convert the value to.").grid(
        row=2, column=0
    )

    value = tk.Entry(new_window)
    value.grid(row=0, column=1)

    from_base = tk.StringVar(new_window)
    from_base.set("16 - HEX")  # default value
    tk.OptionMenu(new_window, from_base, "16 - HEX", "10 - DEC", "2 - BIN").grid(
        row=1, column=1
    )

    to_base = tk.StringVar(new_window)
    to_base.set("10 - DEC")  # default value
    tk.OptionMenu(new_window, to_base, "16 - HEX", "10 - DEC", "2 - BIN").grid(
        row=2, column=1
    )

    output_entry = tk.Entry(new_window)
    output_entry.grid(row=3, column=0, columnspan=2)

    tk.Button(
        new_window,
        text="Convert",
        command=lambda: convert_value(
            value.get(), from_base.get(), to_base.get(), output_entry
        ),
    ).grid(row=4, column=0, columnspan=2, sticky=tk.W)


def update_help_text(event, help_text, help_entry):
    help_entry["state"] = "normal"
    help_entry.delete(1.0, tk.END)
    help_entry.insert(tk.END, help_text.get(str(event.widget), ""))
    help_entry["state"] = "disabled"


def create_help_box(root, help_text):
    help_entry = tk.Text(root, state="disabled", width=50, height=10)
    help_entry.grid(row=0, column=3, rowspan=7, sticky=(tk.N, tk.S, tk.W, tk.E))

    # Bind focus events to update help text
    for widget in root.winfo_children():
        if isinstance(widget, tk.Entry):
            widget.bind(
                "<FocusIn>",
                lambda event: update_help_text(event, help_text, help_entry),
            )

    return help_entry


def main():
    root = tk.Tk()
    root.title("Binary Patching Tool")

    # Add Arch mode selection
    tk.Label(root, text="Architecture Mode").grid(row=10)
    arch_mode = tk.StringVar(root)
    arch_mode.set("64-bit")  # default value
    tk.OptionMenu(root, arch_mode, "32-bit", "64-bit").grid(row=10, column=1)

    # File Selection
    tk.Label(root, text="File Path").grid(row=0)
    tk.Label(root, text="Offset").grid(row=1)
    tk.Label(root, text="Offset Base").grid(row=2)
    tk.Label(root, text="Current Instruction").grid(row=3)
    tk.Label(root, text="New Instruction").grid(row=4)

    file_path = tk.Entry(root)
    offset = tk.Entry(root)
    instruction = tk.Entry(root)
    new_instruction = tk.Entry(root)

    file_path.grid(row=0, column=1)
    offset.grid(row=1, column=1)
    instruction.grid(row=3, column=1)
    new_instruction.grid(row=4, column=1)

    offset_base = tk.StringVar(root)
    offset_base.set("16 - HEX")  # default value
    tk.OptionMenu(root, offset_base, "16 - HEX", "10 - DEC", "2 - BIN").grid(
        row=2, column=1
    )

    # Binary
    tk.Label(root, text="Binary:", fg="red").grid(row=7, column=0)
    bin_entry = tk.Entry(root, fg="red")
    bin_entry.grid(row=7, column=1)

    # Decimal
    tk.Label(root, text="Decimal:", fg="green").grid(row=8, column=0)
    dec_entry = tk.Entry(root, fg="green")
    dec_entry.grid(row=8, column=1)

    # Hexadecimal
    tk.Label(root, text="Hexadecimal:", fg="blue").grid(row=9, column=0)
    hex_entry = tk.Entry(root, fg="blue")
    hex_entry.grid(row=9, column=1)

    tk.Button(root, text="Browse", command=lambda: browse_files(file_path)).grid(
        row=0, column=2
    )

    tk.Button(
        root,
        text="Read",
        command=lambda: read_instruction(
            file_path.get(),
            offset.get(),
            instruction,
            bin_entry,
            hex_entry,
            dec_entry,
            int(offset_base.get().split(" ")[0]),
            arch_mode.get(),
        ),
    ).grid(row=1, column=2)
    tk.Button(
        root,
        text="Patch",
        command=lambda: patch_binary(
            file_path.get(),
            offset.get(),
            new_instruction.get(),
            int(offset_base.get().split(" ")[0]),
            arch_mode.get(),
        ),
    ).grid(row=5, column=1, sticky=tk.W)

    tk.Button(
        root,
        text="Patch",
        command=lambda: patch_binary(
            file_path.get(),
            offset.get(),
            new_instruction.get(),
            int(offset_base.get().split(" ")[0]),
            arch_mode.get(),
            root,
        ),
    ).grid(row=5, column=1, sticky=tk.W)

    tk.Button(
        root,
        text="Offset Calculator",
        command=lambda: open_offset_calculator(file_path),
    ).grid(row=6, column=1, sticky=tk.W)

    tk.Button(root, text="Conversion Tool", command=open_conversion_tool).grid(
        row=10, column=3, sticky=tk.W
    )

    help_text = {
        ".!entry": "Enter the path to the executable file. Click 'Browse' to select the file.",
        ".!entry2": "Enter the file offset of the instruction you want to patch. You can calculate this using the Offset Calculator.",
        ".!entry3": "This field displays the current instruction at the given offset. Click 'Read' to update it.",
        ".!entry4": "Enter the new instruction as a hexadecimal number. For example, enter 'EB' for a JMP instruction.",
    }

    help_entry = create_help_box(root, help_text)

    
    
    
    
    # Set a minimum size for the window
    root.minsize(1400, 720)  # Modify these values as needed
    # Set a fixed size for the window
    root.geometry("1400x720")  # Modify these values as needed

    # Add Badboy offset section
    tk.Label(root, text="Badboy Offset").grid(row=13)
    bad_boy_offset_entry = tk.Entry(root)
    bad_boy_offset_entry.grid(row=13, column=1)

    # Add search string functionality
    tk.Label(root, text="String to Search").grid(row=11)
    search_string_entry = tk.Entry(root)
    search_string_entry.grid(row=11, column=1)
    output_text = tk.Text(root, state="normal", width=40, height=10)
    output_text.grid(row=12, column=0, columnspan=3)

    output_text.tag_configure("binary", foreground="red")
    output_text.tag_configure("decimal", foreground="green")
    output_text.tag_configure("hex", foreground="blue")

    tk.Button(
        root,
        text="Search String",
        command=lambda: search_string_in_binary(
            file_path.get(),
            search_string_entry.get(),
            bad_boy_offset_entry,
            output_text,
        ),
    ).grid(row=11, column=2)

    # Add RVA, IAT, and ITA
    tk.Label(root, text="Relative Virtual Address (RVA)").grid(row=14)
    rva_entry = tk.Entry(root)
    rva_entry.grid(row=14, column=1)

    tk.Label(root, text="Import Address Table (IAT)").grid(row=15)
    iat_entry = tk.Entry(root)
    iat_entry.grid(row=15, column=1)

    tk.Label(root, text="Import Table Address (ITA)").grid(row=16)
    ita_entry = tk.Entry(root)
    ita_entry.grid(row=16, column=1)

    tk.Button(
        root,
        text="Get RVA",
        command=lambda: calculate_rva(file_path.get(), rva_entry),
    ).grid(row=14, column=2)

    tk.Button(
        root,
        text="Get IAT",
        command=lambda: calculate_iat(file_path.get(), iat_entry),
    ).grid(row=15, column=2)

    tk.Button(
        root,
        text="Get ITA",
        command=lambda: calculate_ita(file_path.get(), ita_entry),
    ).grid(row=16, column=2)

    tk.Button(
        root,
        text="Unpack PE",
        command=lambda: unpack_binary(file_path.get(), root),
    ).grid(row=19, column=2)

    # Buttons calling respective functions
    entry_point_entry = tk.Entry(root)
    entry_point_entry.grid(row=0, column=11)
    tk.Button(
        root,
        text="Identify Entry Point",
        command=lambda: identify_entry_point(file_path.get(), entry_point_entry),
    ).grid(row=0, column=10)

    unpacking_stub_entry = tk.Entry(root)
    unpacking_stub_entry.grid(row=1, column=11)
    tk.Button(
        root,
        text="Locate Unpacking Stub",
        command=lambda: locate_unpacking_stub(file_path.get(), unpacking_stub_entry),
    ).grid(row=1, column=10)

    import_table_entry = tk.Entry(root)
    import_table_entry.grid(row=2, column=11)
    tk.Button(
        root,
        text="Identify Import Table",
        command=lambda: identify_import_table(file_path.get(), import_table_entry),
    ).grid(row=2, column=10)

    import_descriptor_entry = tk.Entry(root)
    import_descriptor_entry.grid(row=3, column=11)
    tk.Button(
        root,
        text="Identify IMAGE_IMPORT_DESCRIPTOR",
        command=lambda: identify_import_descriptor(
            file_path.get(), import_descriptor_entry
        ),
    ).grid(row=3, column=10)

    first_thunk_entry = tk.Entry(root)
    first_thunk_entry.grid(row=4, column=11)
    tk.Button(
        root,
        text="Identify First Thunk",
        command=lambda: identify_first_thunk(file_path.get(), first_thunk_entry),
    ).grid(row=4, column=10)

    original_first_thunk_entry = tk.Entry(root)
    original_first_thunk_entry.grid(row=5, column=11)
    tk.Button(
        root,
        text="Identify Original First Thunk",
        command=lambda: identify_original_first_thunk(
            file_path.get(), original_first_thunk_entry
        ),
    ).grid(row=5, column=10)

    modify_unpacking_stub_entry = tk.Entry(root)
    modify_unpacking_stub_entry.grid(row=6, column=11)
    tk.Button(
        root,
        text="Modify Unpacking Stub",
        command=lambda: modify_unpacking_stub(
            file_path.get(), modify_unpacking_stub_entry
        ),
    ).grid(row=6, column=10)

    restore_iat_entry = tk.Entry(root)
    restore_iat_entry.grid(row=7, column=11)
    tk.Button(
        root,
        text="Restore IAT",
        command=lambda: restore_iat(file_path.get(), restore_iat_entry),
    ).grid(row=7, column=10)

    
    
    
    
    # Original Entry Point
    # tk.Label(root, text="Original Entry Point (OEP)").grid(row=8, column=10)  # Remove this line
    oep_entry = tk.Entry(root)
    oep_entry.grid(row=8, column=11)  # Move this line up to row=8, column=11
    tk.Button(
        root,
        text="Identify OEP",
        command=lambda: identify_oep(file_path.get(), oep_entry),
    ).grid(row=8, column=10)  # Move this line up to row=8, column=10

    # Dump Unpacked Executable
    # tk.Label(root, text="Dump Unpacked Executable").grid(row=9, column=10)  # Remove this line
    dump_entry = tk.Entry(root)
    dump_entry.grid(row=9, column=11)  # Move this line up to row=9, column=11
    tk.Button(
        root,
        text="Dump Unpacked",
        command=lambda: dump_unpacked_executable(file_path.get(), dump_entry),
    ).grid(row=9, column=10)  # Move this line up to row=9, column=10

    # Import Table RVA
    # tk.Label(root, text="Import Table RVA").grid(row=10, column=10)  # Remove this line
    import_table_rva_entry = tk.Entry(root)
    import_table_rva_entry.grid(row=10, column=11)  # Move this line up to row=10, column=11
    tk.Button(
        root,
        text="Identify Import Table RVA",
        command=lambda: identify_import_table_rva(file_path.get(), import_table_rva_entry),
    ).grid(row=10, column=10)  # Move this line up to row=10, column=10

    # Fix Dump
    # tk.Label(root, text="Fix Dump").grid(row=11, column=10)  # Remove this line
    fix_dump_entry = tk.Entry(root)
    fix_dump_entry.grid(row=11, column=11)  # Move this line up to row=11, column=11
    tk.Button(
        root,
        text="Fix Dump",
        command=lambda: fix_dump(file_path.get(), fix_dump_entry),
    ).grid(row=11, column=10)  # Move this line up to row=11, column=10

    root.mainloop()

if __name__ == "__main__":
    main()
