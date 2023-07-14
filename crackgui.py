# crack8gui.py
import os
import tkinter as tk
from tkinter import filedialog, messagebox
import binascii
import platform
import pefile
import lief
from capstone import *
from keystone import *


def search_string_in_binary(file_path, string_to_search, bad_boy_offset_entry, output_text):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        # Search for the string as UTF-8 and UTF-16 encoded bytes
        string_to_search_bytes_utf8 = bytes(string_to_search, 'utf-8')
        string_to_search_bytes_utf16 = string_to_search.encode('utf-16')[2:]  # Ignore BOM

        for encoding, string_to_search_bytes in [('utf-8', string_to_search_bytes_utf8), ('utf-16', string_to_search_bytes_utf16)]:
            start_index = 0
            found_indices = []
            while start_index < len(data):
                index = data.find(string_to_search_bytes, start_index)
                if index != -1:
                    found_indices.append(hex(index))
                    start_index = index + 1
                else:
                    break

            output_text.insert(tk.END, f"Search results for '{string_to_search}' in {encoding}:\n")
            if found_indices:
                for offset_str in found_indices:
                    offset = int(offset_str, 16)
                    end_of_string = data.find(b'\x00\x00' if encoding == 'utf-16' else b'\x00', offset)  # Search for null terminator starting from offset
                    string_contents = data[offset:end_of_string].decode(encoding, errors='replace')
                    output_text.insert(tk.END, f"Found at offset: ", "decimal")
                    output_text.insert(tk.END, f"{offset_str}\n", "hex")
                    output_text.insert(tk.END, f"String Contents: {string_contents}\n")
                    
                    bad_boy_offset_entry.delete(0, tk.END)
                    bad_boy_offset_entry.insert(0, offset_str)  # Set Badboy offset to the found offset

                    # You should define code_section_start_offset
                    code_section_start_offset = 0x400000  # example value

                    # Find the first conditional jump instruction before the "Bad Boy" string
                    cs = Cs(CS_ARCH_X86, CS_MODE_32)  # Use CS_MODE_64 for 64-bit binaries
                    cs.detail = True  # Include instruction details
                    jmp_instructions = ['je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe', 'jmp']
                    
                    # Starting from the offset of "Bad Boy" and going backward until the start of the code section
                    for i in range(offset, code_section_start_offset, -1):
                        # We need to disassemble in blocks as Capstone may need more bytes to accurately disassemble an instruction
                        # 15 is the maximum length of an x86/x86_64 instruction
                        instruction_bytes = data[i-15:i]
                        instructions = list(cs.disasm(instruction_bytes, i-15))
                        
                        if instructions:
                            last_instruction = instructions[-1]
                            if last_instruction.mnemonic in jmp_instructions:
                                output_text.insert(tk.END, f"Found conditional jump at offset: ", "decimal")
                                output_text.insert(tk.END, f"{hex(last_instruction.address)}\n", "hex")
                                break
            else:
                output_text.insert(tk.END, "String not found.\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error: {str(e)}\n")



def patch_binary(file_path, offset, new_instruction, offset_base, arch_mode):
    try:
        with open(file_path, "rb") as f:
            data = bytearray(f.read())
            
        # Convert offset to integer based on base
        offset = int(offset, offset_base)
        print(f"Offset: {offset}")  # Debugging

        # Use Keystone to assemble new_instruction into machine code
        ks = Ks(KS_ARCH_X86, arch_mode)  # Use selected architecture mode
        encoding, count = ks.asm(new_instruction)
        print(f"Encoding: {encoding}, Count: {count}")  # Debugging
        new_instruction_machine_code = bytes(encoding)

        # Replace the instruction at the specified offset with new_instruction_machine_code
        for i in range(len(new_instruction_machine_code)):
            data[offset + i] = new_instruction_machine_code[i]

        with open(file_path, "wb") as f:
            f.write(data)
        messagebox.showinfo("Success", "File patched successfully.")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        
    
def browse_files(file_path_entry):
    try:
        file_path_entry.delete(0, tk.END)  # Remove current file path
        app_path = filedialog.askopenfilename(filetypes=[('Executable Files', '*.exe'), ('Mach-O Files', '*.macho'), ('App Files', '*.app')])  # Open file dialog
        if app_path.endswith('.app'):
            # Handle .app files by finding the actual executable inside the bundle
            app_name = os.path.splitext(os.path.basename(app_path))[0]
            executable_path = os.path.join(app_path, "Contents", "MacOS", app_name)
            file_path_entry.insert(0, executable_path)  # Insert new file path
        else:
            # For .exe and .macho files, use the selected file path directly
            file_path_entry.insert(0, app_path)  # Insert new file path

        # Determine the operating system
        os_name = platform.system()
        if os_name == "Windows":
            # Parse the binary file using pefile
            pe = pefile.PE(app_path)
            # Search for all instances of the string "Bad boy"
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if entry.name is not None and entry.name.string == "Bad boy":
                    print(f"Found 'Bad boy' at offset: {entry.directory.entries[0].data.struct.OffsetToData}")
        elif os_name == "Darwin":
            # Parse the binary file using lief
            binary = lief.parse(app_path)
            # Search for all instances of the string "Bad boy"
            for section in binary.sections:
                if "Bad boy" in section.content:
                    print(f"Found 'Bad boy' in section: {section.name}")
        else:
            print("Unsupported operating system.")
    except Exception as e:
        print("An error occurred: ", str(e))




def read_instruction(file_path, offset, instruction_entry, bin_entry, hex_entry, dec_entry, offset_base, arch_mode):
    try:
        # Check if offset is valid
        if not offset:
            raise ValueError("Offset cannot be empty.")
        # Convert offset to integer based on base
        offset = int(offset, offset_base)
        with open(file_path, "rb") as f:
            f.seek(offset)
            instruction = f.read(15)  # Max length of x86/x86_64 instruction is 15 bytes
        # Create a Capstone instance for disassembling
        cs = Cs(CS_ARCH_X86, arch_mode)  # Use selected architecture mode
        # Disassemble the instruction
        disassembled = list(cs.disasm(instruction, offset))  # offset is used as the instruction's address
        if disassembled:
            # If disassembly was successful, update the instruction_entry with the disassembled instruction
            disassembled_instruction = disassembled[0]
            instruction_entry.delete(0, tk.END)
            instruction_entry.insert(0, f"{disassembled_instruction.mnemonic} {disassembled_instruction.op_str}")
            # Convert the instruction to binary, hexadecimal, and decimal and update the respective entries
            bin_value = ' '.join(f'{byte:08b}' for byte in instruction)
            hex_value = ' '.join(f'{byte:02x}' for byte in instruction)
            dec_value = ' '.join(f'{byte:03}' for byte in instruction)
            
            bin_entry.delete(0, tk.END)
            bin_entry.insert(0, bin_value)
            hex_entry.delete(0, tk.END)
            hex_entry.insert(0, hex_value)
            dec_entry.delete(0, tk.END)
            dec_entry.insert(0, dec_value)
        else:
            # If disassembly was not successful, update the instruction_entry with an error message
            instruction_entry.delete(0, tk.END)
            instruction_entry.insert(0, "Could not disassemble instruction")
    except Exception as e:
        messagebox.showerror("Error", str(e))





def calculate_offset(base_virt_addr, base_file_offset, instr_virt_addr):
    try:
        # Convert inputs to integers
        base_virt_addr = int(base_virt_addr, 16)
        base_file_offset = int(base_file_offset, 16)
        instr_virt_addr = int(instr_virt_addr, 16)

        # Calculate offset within section and file offset
        offset_within_section = instr_virt_addr - base_virt_addr
        file_offset = base_file_offset + offset_within_section

        messagebox.showinfo("File Offset", f"The file offset of the instruction is {file_offset}.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def open_offset_calculator():
    new_window = tk.Toplevel()
    new_window.title("Offset Calculator")

    tk.Label(new_window, text="Base Virtual Address: The starting memory address of the section where the instruction resides. You can find this in the section headers in Ghidra.").grid(row=0, columnspan=2)
    tk.Label(new_window, text="Base File Offset: The starting file offset of the section. You can find this in the section headers in Ghidra.").grid(row=1, columnspan=2)
    tk.Label(new_window, text="Instruction Virtual Address: The memory address of the instruction you want to patch. You found this when you identified the instruction in Ghidra.").grid(row=2, columnspan=2)

    base_virt_addr = tk.Entry(new_window)
    base_file_offset = tk.Entry(new_window)
    instr_virt_addr = tk.Entry(new_window)

    base_virt_addr.grid(row=0, column=2)
    base_file_offset.grid(row=1, column=2)
    instr_virt_addr.grid(row=2, column=2)

    tk.Button(new_window, text="Calculate", command=lambda: calculate_offset(base_virt_addr.get(), base_file_offset.get(), instr_virt_addr.get())).grid(row=3, column=1, sticky=tk.W)


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

    tk.Label(new_window, text="Value: The value you want to convert.").grid(row=0, column=0)
    tk.Label(new_window, text="From: The base of the value you want to convert.").grid(row=1, column=0)
    tk.Label(new_window, text="To: The base you want to convert the value to.").grid(row=2, column=0)

    value = tk.Entry(new_window)
    value.grid(row=0, column=1)

    from_base = tk.StringVar(new_window)
    from_base.set("16 - HEX")  # default value
    tk.OptionMenu(new_window, from_base, "16 - HEX", "10 - DEC", "2 - BIN").grid(row=1, column=1)
    
    to_base = tk.StringVar(new_window)
    to_base.set("10 - DEC")  # default value
    tk.OptionMenu(new_window, to_base, "16 - HEX", "10 - DEC", "2 - BIN").grid(row=2, column=1)

    output_entry = tk.Entry(new_window)
    output_entry.grid(row=3, column=0, columnspan=2)
    
    tk.Button(new_window, text="Convert", command=lambda: convert_value(value.get(), from_base.get(), to_base.get(), output_entry)).grid(row=4, column=0, columnspan=2, sticky=tk.W)


def update_help_text(event, help_text, help_entry):
    help_entry['state'] = 'normal'
    help_entry.delete(1.0, tk.END)
    help_entry.insert(tk.END, help_text.get(str(event.widget), ""))
    help_entry['state'] = 'disabled'


def create_help_box(root, help_text):
    help_entry = tk.Text(root, state='disabled', width=50, height=10)
    help_entry.grid(row=0, column=3, rowspan=7, sticky=(tk.N, tk.S, tk.W, tk.E))

    # Bind focus events to update help text
    for widget in root.winfo_children():
        if isinstance(widget, tk.Entry):
            widget.bind("<FocusIn>", lambda event: update_help_text(event, help_text, help_entry))

    return help_entry


def main():
    root = tk.Tk()
    root.title("Binary Patcher")
    
    # Add buttons for selecting architecture
    arch_mode = tk.IntVar()
    tk.Radiobutton(root, text="x86", variable=arch_mode, value=CS_MODE_32).grid(row=5, column=0)
    tk.Radiobutton(root, text="x64", variable=arch_mode, value=CS_MODE_64).grid(row=6, column=0)
    arch_mode.set(CS_MODE_64)  # Default to x64

    tk.Label(root, text="Executable Path").grid(row=0)
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
    tk.OptionMenu(root, offset_base, "16 - HEX", "10 - DEC", "2 - BIN").grid(row=2, column=1)

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



    tk.Button(root, text="Browse", command=lambda: browse_files(file_path)).grid(row=0, column=2)
    tk.Button(root, text="Read", command=lambda: read_instruction(file_path.get(), offset.get(), instruction, bin_entry, hex_entry, dec_entry, int(offset_base.get().split(' ')[0]), arch_mode.get())).grid(row=1, column=2)
    tk.Button(root, text="Patch", command=lambda: patch_binary(file_path.get(), offset.get(), new_instruction.get(), int(offset_base.get().split(' ')[0]), arch_mode.get())).grid(row=5, column=1, sticky=tk.W)

    tk.Button(root, text="Offset Calculator", command=open_offset_calculator).grid(row=6, column=1, sticky=tk.W)
    tk.Button(root, text="Conversion Tool", command=open_conversion_tool).grid(row=10, column=1, sticky=tk.W)

    help_text = {
        ".!entry": "Enter the path to the executable file. Click 'Browse' to select the file.",
        ".!entry2": "Enter the file offset of the instruction you want to patch. You can calculate this using the Offset Calculator.",
        ".!entry3": "This field displays the current instruction at the given offset. Click 'Read' to update it.",
        ".!entry4": "Enter the new instruction as a hexadecimal number. For example, enter 'EB' for a JMP instruction."
    }

    help_entry = create_help_box(root, help_text)

    
    # Set a minimum size for the window
    root.minsize(1200, 600)  # Modify these values as needed
    # Set a fixed size for the window
    root.geometry("1200x600")  # Modify these values as needed

    
    # Add Badboy offset section
    tk.Label(root, text="Badboy Offset").grid(row=13)
    bad_boy_offset_entry = tk.Entry(root)
    bad_boy_offset_entry.grid(row=13, column=1)

    # Add search string functionality
    tk.Label(root, text="String to Search").grid(row=11)
    search_string_entry = tk.Entry(root)
    search_string_entry.grid(row=11, column=1)
    output_text = tk.Text(root, state='normal', width=40, height=10)
    output_text.grid(row=12, column=0, columnspan=3)
    
    output_text.tag_configure("binary", foreground="red")
    output_text.tag_configure("decimal", foreground="green")
    output_text.tag_configure("hex", foreground="blue")

    tk.Button(root, text="Search String", command=lambda: search_string_in_binary(file_path.get(), search_string_entry.get(), bad_boy_offset_entry, output_text)).grid(row=11, column=2)

    root.mainloop()

    

if __name__ == '__main__':
    main()
