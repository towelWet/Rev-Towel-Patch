# crack16gui.py

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
import difflib
import subprocess
import obfuscation_detection as od





def expected_reg(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Depending on the software type, you might need to use different tools for analysis.
        # The example below assumes a PE file, but for macOS apps, you might need to use another method.

        pe = pefile.PE(data)
        product_name = pe.get_string(pe.get_file_header().ProductName)
        version = pe.get_string(pe.get_file_header().ProductVersion)

        # Identify the key values that are used to activate the software.
        keys = []
        for entry in pe.sections:
            if entry.Name.startswith("REG_"):
                keys.append(entry.Name[4:])

        # Generate the expected format for a valid .reg file.
        reg_file = ""
        for key in keys:
            reg_file += f"REG_ADD {key} {product_name} {version}\n"

        return reg_file

    except Exception as e:
        print(e)
        return None

    
def generate_expected_reg(file_path):
    """Generates the expected format for a valid .reg file based on the target software's registration scheme."""

    reg_file = expected_reg(file_path)

    if reg_file is not None:
        with open(file_path + ".reg", "w") as f:
            f.write(reg_file)

        messagebox.showinfo("Expected Reg", "The expected .reg file has been generated.")
    else:
        messagebox.showinfo("Expected Reg", "The target software does not have a valid registration scheme.")
    
    
    

def create_rarun2_config(args, env_vars, config_file_name):
    """
    Creates a rarun2 configuration file.

    Parameters:
        args (list of str): A list of arguments for the program.
        env_vars (dict): A dictionary of environment variables for the program.
        config_file_name (str): The name of the configuration file to be saved.

    Returns:
        None
    """
    program_path = os.path.realpath(__file__)
    config_file_path = os.path.join(os.path.dirname(program_path), config_file_name)
    
    with open(config_file_path, 'w') as file:
        file.write(f"#!/usr/bin/rarun2\nprogram={program_path}\n")

        for i, arg in enumerate(args):
            file.write(f"arg{i + 1}={arg}\n")

        for var, value in env_vars.items():
            file.write(f"setenv={var}={value}\n")

# Call the function to create/update the configuration file
args = ["arg1", "arg2"]
env_vars = {"ENV_VAR": "value"}
config_file_name = "config.rr2"

create_rarun2_config(args, env_vars, config_file_name)


def run_radare2_command(binary_file, command):
    radare2_command = f"r2 -q0 {binary_file} -c '{command};q'"
    result = subprocess.run(radare2_command, shell=True, capture_output=True)
    return result.stdout.decode()

def automatic_deobfuscation(binary_file):
    """
    Automatically detects and reports common obfuscation techniques in the provided binary file.

    Parameters:
        binary_file (str): The path to the binary file to be analyzed.

    Returns:
        result (str): The analysis result.
    """
    # Run a radare2 command to disassemble the binary
    disassembly = run_radare2_command(binary_file, 'aaa;pdf')

    # Look for potential obfuscation techniques in the disassembly
    result = ""

    # Obfuscation might involve unusual or complex control flow constructs,
    # such as jumps to computed addresses. Let's look for these.
    if 'jmp eax' in disassembly or 'jmp [eax]' in disassembly:
        result += "Potential control flow obfuscation detected: computed jump.\n"

    # Obfuscation might involve data being transformed through various arithmetic operations.
    # Let's look for sequences of arithmetic operations.
    if 'add eax,' in disassembly and 'sub eax,' in disassembly:
        result += "Potential data obfuscation detected: sequences of arithmetic operations.\n"

    # Obfuscation might involve the use of rarely used or complex instructions.
    # Let's look for these.
    if 'xlat' in disassembly:
        result += "Potential instruction obfuscation detected: rarely used instructions.\n"

    if result == "":
        result = "No common obfuscation techniques detected."

    return result


def binary_diffing(binary_file_1, binary_file_2):
    """
    Compares two binary files and finds differences between them.

    Parameters:
        binary_file_1 (str): The path to the first binary file to be compared.
        binary_file_2 (str): The path to the second binary file to be compared.
    """
    # Run the diffoscope command and capture the output
    cmd = ["diffoscope", binary_file_1, binary_file_2]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # The differences are in the stdout attribute of the result
    differences = result.stdout

    # Also capture stderr
    if result.stderr.strip() != "":
        differences += "\nErrors or warnings:\n" + result.stderr

    # Create a new Toplevel window
    new_window = tk.Toplevel()
    new_window.title("Binary Diffing Results")

    # If there are no differences, show a message indicating that
    if differences.strip() == "":
        differences = "The files are identical."

    # Create a Text widget to display the differences
    text_widget = tk.Text(new_window)
    text_widget.insert(tk.END, differences)
    text_widget.pack()

    # Set the focus to the new window
    new_window.focus_set()




def compare_binaries():
    binary_file_1 = filedialog.askopenfilename()
    binary_file_2 = filedialog.askopenfilename()
    differences = binary_diffing(binary_file_1, binary_file_2)

    # Create a new tkinter window
    window = tk.Toplevel()
    window.title("Binary Diff Results")

    # Create a text widget and insert the differences
    text_widget = tk.Text(window)
    text_widget.pack(fill='both', expand=True)
    text_widget.insert('1.0', differences)


def binary_analysis_report(file_path, root):
    # Open a new window
    report_window = tk.Toplevel(root)
    report_window.title("Binary Analysis Report")
    report = ""

    parsers = {
        '.exe': lief.PE.parse,
        '.app': lief.MachO.parse
    }

    # Generate the binary report
    try:
        ext = os.path.splitext(file_path)[1]
        if ext in parsers:
            binary = parsers[ext](file_path)

            report_parts = [
                str(binary.header),
                *(str(section) for section in getattr(binary, 'sections', [])),
                *(str(symbol) for symbol in getattr(binary, 'symbols', [])),
            ]

            report = "\n".join(report_parts)
        else:
            report = "Unsupported file type"
    except Exception as e:
        report = "Failed to generate report: " + str(e)

    # Display the report in the new window
    report_label = tk.Label(report_window, text=report)
    report_label.pack()



def find_code_cave(size):
    global pe
    try:
        # Initialize a counter and start index
        counter = 0
        start_index = None

        # Iterate over the memory
        for section in pe.sections:
            if section.SizeOfRawData != 0:  # Ignore sections with no data
                for i in range(section.SizeOfRawData):
                    # If we find a null byte or NOP, increase the counter and set start index if not already set
                    if section.get_data()[i:i+1] in [b'\x00', b'\x90']:
                        counter += 1
                        if start_index is None:
                            start_index = i
                    # If we don't find a null byte or NOP, reset the counter and start index
                    else:
                        counter = 0
                        start_index = None

                    # If the counter reaches the desired size, return the start index
                    if counter == size:
                        return start_index + section.VirtualAddress

        # If we didn't find a large enough code cave, return None
        return None
    except Exception as e:
        # Handle any exceptions or error cases
        messagebox.showerror("Error", str(e))
        return None

    
    
def keygen():
    """
    This function should implement the key generation logic.
    """
    # TODO: Implement the key generation logic here
    pass
    

    
    
    

def open_keygen_window():
    """
    This function opens a new window with keygen-related components.
    """
    keygen_window = tk.Toplevel()
    keygen_window.title("Keygen")

    tk.Label(keygen_window, text="Enter your name:").grid(row=0, column=0)
    name_entry = tk.Entry(keygen_window)
    name_entry.grid(row=0, column=1)

    tk.Label(keygen_window, text="Generated key:").grid(row=1, column=0)
    key_entry = tk.Entry(keygen_window)
    key_entry.grid(row=1, column=1)

    tk.Button(
        keygen_window,
        text="Generate Key",
        command=lambda: key_entry.insert(0, keygen(name_entry.get())),  # Call the keygen function with the name entered by the user
    ).grid(row=2, column=0, columnspan=2)
    
    
    
    
def create_code_cave(binary):
    try:
        with open(binary, "ab") as file:
            file.write(b"\x90" * 100)  # Append 100 NOP instructions to the end of the file
        print("Code cave created.")
    except Exception as e:
        print("Error:", str(e))

    
def identify_anti_debugging_techniques(file_path):
    results = []  # Define the results list at the top of the function
    try:
        # Attempt to parse as a PE file
        pe = pefile.PE(file_path)

        # Check for the use of the IsDebuggerPresent function
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name == b'IsDebuggerPresent':
                    results.append("Identify Anti Debugging Techniques function is in development")

    except pefile.PEFormatError:
        # If a PEFormatError is raised, it's not a PE file
        try:
            # Attempt to parse as a Mach-O file
            binary = lief.parse(file_path)

            # TODO: Implement Mach-O specific anti-debugging detection
            results.extend(["Mach-O Technique 1", "Mach-O Technique 2"])

        except lief.read_out_of_bound:
            # If a read_out_of_bound exception is raised, it's not a Mach-O file
            results.append("File is not a PE or Mach-O file.")

    return results

                
                
def display_results(results):
    """
    Displays the results in a new Tkinter window.

    Parameters:
        results (list of str): The list of results to be displayed.

    Returns:
        None
    """
    # Create a new Toplevel window
    new_window = tk.Toplevel()
    new_window.title("Anti-Debugging Techniques")

    # Create a Text widget to display the results
    text_widget = tk.Text(new_window)
    text_widget.insert(tk.END, '\n'.join(results))
    text_widget.pack()

    # Set the focus to the new window
    new_window.focus_set()


def interact_tls_callbacks(file_path):
    """
    Interacts with the TLS callbacks of a PE file.

    Args:
        file_path (str): The path to the PE file.
    """

    # Load the PE file
    pe = pefile.PE(file_path)

    # Check if the PE file has a TLS section
    if not hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        print('The PE file does not have a TLS section.')
        return

    # Print the start address of the TLS callback array
    print(f"Start address of the TLS callback array: {pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks}")

    # Iterate over the TLS callbacks and print their addresses
    callback_array_rva = pe.get_rva_from_offset(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)
    index = 0
    while True:
        callback_rva = pe.get_dword_from_data(pe.get_data(callback_array_rva + index * 4, 4), 0)
        if callback_rva == 0:
            break
        print(f"TLS callback at RVA {callback_rva}")
        index += 1


def interact_export_table(binary, export_table_entry):
    try:
        pe = pefile.PE(binary)
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print("Exports:")
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print(f"{exp.name} at {hex(exp.address)}")
        else:
            print("No export table found.")
    except pefile.PEFormatError:
        print("Invalid PE file.")
    except Exception as e:
        print("Error:", str(e))




def interact_resource_table(file_path):
    """
    Interacts with the Resource Table of a PE file.

    Args:
        file_path (str): The path to the PE file.
    """

    # Load the PE file
    pe = pefile.PE(file_path)

    # Check if the PE file has a Resource Table
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        print('The PE file does not have a Resource Table.')
        return

    # Iterate over the entries in the Resource Table
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if resource_type.name is not None:
            print(f"Resource Type: {resource_type.name}")
        else:
            print(f"Resource Type: {pefile.RESOURCE_TYPE.get(resource_type.struct.Id)}")

        if resource_type.directory is not None:
            for resource_id in resource_type.directory.entries:
                if resource_id.name is not None:
                    print(f"Resource Name: {resource_id.name}")
                else:
                    print(f"Resource ID: {resource_id.struct.Id}")

                if resource_id.directory is not None:
                    for resource_lang in resource_id.directory.entries:
                        print(f"Language ID: {resource_lang.struct.Id}")


        
def interact_relocation_table(binary, relocation_table_entry):
    try:
        pe = pefile.PE(binary)
        if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            print("Relocations:")
            for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC.entries:
                print(f"{hex(base_reloc.struct.VirtualAddress)}")
        else:
            print("No relocation table found.")
    except pefile.PEFormatError:
        print("Invalid PE file.")
    except Exception as e:
        print("Error:", str(e))
    


def interact_overlay(binary, overlay_entry):
    try:
        pe = pefile.PE(binary)
        offset = pe.get_overlay_data_start_offset()
        if offset is not None:
            print("Overlay found at offset:", hex(offset))
            overlay = pe.get_overlay()
            with open(f"{binary}_overlay", "wb") as overlay_file:
                overlay_file.write(overlay)
            print("Overlay extracted.")
        else:
            print("No overlay found.")
    except pefile.PEFormatError:
        print("Invalid PE file.")
    except Exception as e:
        print("Error:", str(e))


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


def dump_unpacked_executable(file_path, unpacked_file_path):
    """
    Reads the packed executable from `file_path`, unpacks it, and then writes the unpacked executable to `unpacked_file_path`.

    Args:
        file_path (str): The path to the packed executable.
        unpacked_file_path (str): The path to save the unpacked executable.
    """

    # Read the packed executable
    with open(file_path, "rb") as packed_file:
        packed_data = packed_file.read()

    # TODO: Unpack the data
    # This is a placeholder. You'll need to replace this with your actual unpacking logic.
    unpacked_data = packed_data  # Replace this with the actual unpacking logic

    # Write the unpacked executable
    with open(unpacked_file_path, "wb") as unpacked_file:
        unpacked_file.write(unpacked_data)

    print(f"Successfully dumped unpacked executable to {unpacked_file_path}")


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
    # Load the PE file
    pe = pefile.PE(file_path)

    # Iterate over the PE's directories
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        # Iterate over the imported functions
        for imp in entry.imports:
            # If the address of the function is 0, it means it was not correctly imported
            if imp.address == 0:
                print(f"Fixing import: {imp.name}")
                # TODO: Implement logic to fix the import
                # This might involve searching for the function in the binary, updating the IAT, etc.

    # Save the fixed executable
    pe.write(filename=f"{file_path}_fixed")



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


def identify_ilt(file_path, ilt_entry):
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            import_table = pe.DIRECTORY_ENTRY_IMPORT
            ilt_rva = import_table[0].original_first_thunk
            pe.close()

            # Update the entry field with the ILT RVA
            ilt_entry.delete(0, tk.END)
            ilt_entry.insert(tk.END, hex(ilt_rva))
        else:
            messagebox.showwarning("Warning", "No import table found.")
    except Exception as e:
        ilt_entry.delete(0, tk.END)
        ilt_entry.insert(tk.END, "Error: " + str(e))

        
        
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


def update_help_text(event, help_text, help_entry, widget):
    widget_name = str(widget)
    if widget_name in help_text:
        help_entry["state"] = "normal"
        help_entry.delete(1.0, tk.END)
        help_entry.insert(tk.END, help_text[widget_name])
        help_entry["state"] = "disabled"

    
    
def create_help_box(root, help_text, pages):
    help_entry = tk.Text(root, state="disabled", width=50, height=10)
    help_entry.grid(row=0, column=3, rowspan=7, sticky=(tk.N, tk.S, tk.W, tk.E))

    for page in pages:
        for widget in page.winfo_children():
            if isinstance(widget, tk.Entry):
                widget.bind(
                    "<FocusIn>",
                    lambda event, widget=widget: update_help_text(event, help_text, help_entry, widget),
                )

    return help_entry



def raise_frame(frame):
    frame.tkraise()

def main():
    root = tk.Tk()
    root.title("Binary Patching Tool")

    # Define the frames (pages)
    page1 = tk.Frame(root)
    page2 = tk.Frame(root)

    # Grid the frames
    for frame in (page1, page2):
        frame.grid(row=0, column=0, sticky='news')

    # Add a button on page1 to navigate to page2
    tk.Button(page1, text="Next Page", command=lambda: raise_frame(page2)).grid(row=100, column=0)  # Assuming row=100 is available

    # Add a button on page2 to navigate back to page1
    tk.Button(page2, text="Previous Page", command=lambda: raise_frame(page1)).grid(row=100, column=0)  # Assuming row=100 is available


    # Add Arch mode selection
    tk.Label(page1, text="Architecture Mode").grid(row=10)
    arch_mode = tk.StringVar(root)
    arch_mode.set("64-bit")  # default value
    tk.OptionMenu(page1, arch_mode, "32-bit", "64-bit").grid(row=10, column=1)

    # File Selection
    tk.Label(page1, text="File Path").grid(row=0)
    tk.Label(page1, text="Offset").grid(row=1)
    tk.Label(page1, text="Offset Base").grid(row=2)
    tk.Label(page1, text="Current Instruction").grid(row=3)
    tk.Label(page1, text="New Instruction").grid(row=4)

    file_path = tk.Entry(page1)
    offset = tk.Entry(page1)
    instruction = tk.Entry(page1)
    new_instruction = tk.Entry(page1)

    file_path.grid(row=0, column=1)
    offset.grid(row=1, column=1)
    instruction.grid(row=3, column=1)
    new_instruction.grid(row=4, column=1)

    offset_base = tk.StringVar(page1)
    offset_base.set("16 - HEX")  # default value
    tk.OptionMenu(page1, offset_base, "16 - HEX", "10 - DEC", "2 - BIN").grid(
        row=2, column=1
    )

    # Binary
    tk.Label(page1, text="Binary:", fg="red").grid(row=7, column=0)
    bin_entry = tk.Entry(page1, fg="red")
    bin_entry.grid(row=7, column=1)

    # Decimal
    tk.Label(page1, text="Decimal:", fg="green").grid(row=8, column=0)
    dec_entry = tk.Entry(page1, fg="green")
    dec_entry.grid(row=8, column=1)

    # Hexadecimal
    tk.Label(page1, text="Hexadecimal:", fg="blue").grid(row=9, column=0)
    hex_entry = tk.Entry(page1, fg="blue")
    hex_entry.grid(row=9, column=1)

    tk.Button(page1, text="Browse", command=lambda: browse_files(file_path)).grid(
        row=0, column=2
    )

    tk.Button(
        page1,
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
        page1,
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
        page1,
        text="Patch",
        command=lambda: patch_binary(
            file_path.get(),
            offset.get(),
            new_instruction.get(),
            int(offset_base.get().split(" ")[0]),
            arch_mode.get(),
            page1,
        ),
    ).grid(row=5, column=1, sticky=tk.W)

    tk.Button(
        page1,
        text="Offset Calculator",
        command=lambda: open_offset_calculator(file_path),
    ).grid(row=6, column=1, sticky=tk.W)

    tk.Button(page1, text="Conversion Tool", command=open_conversion_tool).grid(
        row=10, column=3, sticky=tk.W
    )




    # Correctly name the keys in the help_text dictionary to match the widget names
    help_text = {
        ".!frame.!entry": "Enter the path to the executable file. Click 'Browse' to select the file.",
        ".!frame.!entry2": "Enter the file offset of the instruction you want to patch. You can calculate this using the Offset Calculator.",
        ".!frame.!entry3": "This field displays the current instruction at the given offset. Click 'Read' to update it.",
        ".!frame.!entry4": "Enter the new instruction as a hexadecimal number. For example, enter 'EB' for a JMP instruction.",
        # ...
    }


    # Create the help box
    create_help_box(root, help_text, [page1, page2])
    
    
    
    # Set a minimum size for the window
    root.minsize(1400, 720)  # Modify these values as needed
    # Set a fixed size for the window
    root.geometry("1400x720")  # Modify these values as needed

    # Add Badboy offset section
    tk.Label(page1, text="Badboy Offset").grid(row=13)
    bad_boy_offset_entry = tk.Entry(page1)
    bad_boy_offset_entry.grid(row=13, column=1)

    # Add search string functionality
    tk.Label(page1, text="String to Search").grid(row=11)
    search_string_entry = tk.Entry(page1)
    search_string_entry.grid(row=11, column=1)
    output_text = tk.Text(page1, state="normal", width=40, height=10)
    output_text.grid(row=12, column=0, columnspan=3)

    output_text.tag_configure("binary", foreground="red")
    output_text.tag_configure("decimal", foreground="green")
    output_text.tag_configure("hex", foreground="blue")

    tk.Button(
        page1,
        text="Search String",
        command=lambda: search_string_in_binary(
            file_path.get(),
            search_string_entry.get(),
            bad_boy_offset_entry,
            output_text,
        ),
    ).grid(row=11, column=2)

    # Add RVA, IAT, and ITA
    tk.Label(page1, text="Relative Virtual Address (RVA)").grid(row=14)
    rva_entry = tk.Entry(page1)
    rva_entry.grid(row=14, column=1)

    tk.Label(page1, text="Import Address Table (IAT)").grid(row=15)
    iat_entry = tk.Entry(page1)
    iat_entry.grid(row=15, column=1)

    tk.Label(page1, text="Import Table Address (ITA)").grid(row=16)
    ita_entry = tk.Entry(page1)
    ita_entry.grid(row=16, column=1)

    tk.Button(
        page1,
        text="Get RVA",
        command=lambda: calculate_rva(file_path.get(), rva_entry),
    ).grid(row=14, column=2)

    tk.Button(
        page1,
        text="Get IAT",
        command=lambda: calculate_iat(file_path.get(), iat_entry),
    ).grid(row=15, column=2)

    tk.Button(
        page1,
        text="Get ITA",
        command=lambda: calculate_ita(file_path.get(), ita_entry),
    ).grid(row=16, column=2)

    tk.Button(
        page1,
        text="Unpack PE",
        command=lambda: unpack_binary(file_path.get(), page1),
    ).grid(row=19, column=2)

    # Add new GUI components on page2
    entry_point_entry = tk.Entry(page2)
    entry_point_entry.grid(row=0, column=1)
    tk.Button(
        page2,
        text="Identify Entry Point",
        command=lambda: identify_entry_point(file_path.get(), entry_point_entry),
    ).grid(row=0, column=0)

    unpacking_stub_entry = tk.Entry(page2)
    unpacking_stub_entry.grid(row=1, column=1)
    tk.Button(
        page2,
        text="Locate Unpacking Stub",
        command=lambda: locate_unpacking_stub(file_path.get(), unpacking_stub_entry),
    ).grid(row=1, column=0)
    
    import_table_entry = tk.Entry(page2)
    import_table_entry.grid(row=2, column=1)
    tk.Button(
        page2,
        text="Identify Import Table",
        command=lambda: identify_import_table(file_path.get(), import_table_entry),
    ).grid(row=2, column=0)



    image_import_descriptor_entry = tk.Entry(page2)
    image_import_descriptor_entry.grid(row=3, column=1)
    tk.Button(
        page2,
        text="Identify IMAGE_IMPORT_DESCRIPTOR",
        command=lambda: identify_image_import_descriptor(file_path.get(), image_import_descriptor_entry),
    ).grid(row=3, column=0)

    
    # Identify First Thunk
    first_thunk_entry = tk.Entry(page2)  # Change page1 to page2
    first_thunk_entry.grid(row=4, column=1)
    tk.Button(
        page2,  # Change page1 to page2
        text="Identify First Thunk",
        command=lambda: identify_first_thunk(file_path.get(), first_thunk_entry),
    ).grid(row=4, column=0)

    # Identify Original First Thunk
    original_first_thunk_entry = tk.Entry(page2)  # Change page1 to page2
    original_first_thunk_entry.grid(row=5, column=1)
    tk.Button(
        page2,  # Change page1 to page2
        text="Identify Original First Thunk",
        command=lambda: identify_original_first_thunk(file_path.get(), original_first_thunk_entry),
    ).grid(row=5, column=0)

    # Modify Unpacking Stub
    modify_unpacking_stub_entry = tk.Entry(page2)  # Change page1 to page2
    modify_unpacking_stub_entry.grid(row=6, column=1)
    tk.Button(
        page2,  # Change page1 to page2
        text="Modify Unpacking Stub",
        command=lambda: modify_unpacking_stub(file_path.get(), modify_unpacking_stub_entry),
    ).grid(row=6, column=0)

    # Restore IAT
    restore_iat_entry = tk.Entry(page2)  # Change page1 to page2
    restore_iat_entry.grid(row=7, column=1)
    tk.Button(
        page2,  # Change page1 to page2
        text="Restore IAT",
        command=lambda: restore_iat(file_path.get(), restore_iat_entry),
    ).grid(row=7, column=0)



    # Original Entry Point
    oep_entry = tk.Entry(page2)
    oep_entry.grid(row=8, column=1)
    tk.Button(
        page2,
        text="Identify OEP",
        command=lambda: identify_oep(file_path.get(), oep_entry),
    ).grid(row=8, column=0)

    # Dump Unpacked Executable
    dump_entry = tk.Entry(page2)
    dump_entry.grid(row=9, column=1)
    tk.Button(
        page2,
        text="Dump Unpacked",
        command=lambda: dump_unpacked_executable(file_path.get(), dump_entry),
    ).grid(row=9, column=0)

    # Import Table RVA
    import_table_rva_entry = tk.Entry(page2)
    import_table_rva_entry.grid(row=10, column=1)
    tk.Button(
        page2,
        text="Identify Import Table RVA",
        command=lambda: identify_import_table_rva(file_path.get(), import_table_rva_entry),
    ).grid(row=10, column=0)

    
    # Add ILT
    tk.Label(page1, text="Import Lookup Table (ILT)").grid(row=17)
    ilt_entry = tk.Entry(page1)
    ilt_entry.grid(row=17, column=1)

    tk.Button(
        page1,
        text="Identify ILT",
        command=lambda: identify_ilt(file_path.get(), ilt_entry),
    ).grid(row=17, column=2)


    tk.Button(
        page1,
        text="Fix Dump",
        command=lambda: fix_dump(file_path.get(), fix_dump_entry),
    ).grid(row=12, column=10)  # Modify row number as needed

    

    # Export Table
    tk.Label(page2, text="Export Table").grid(row=13, column=0)
    export_table_entry = tk.Entry(page2)
    export_table_entry.grid(row=13, column=1)
    tk.Button(
        page2,
        text="Interact Export Table",
        command=lambda: interact_export_table(file_path.get(), export_table_entry),
    ).grid(row=13, column=0)

    # Resource Table
    tk.Label(page2, text="Resource Table").grid(row=14, column=0)
    resource_table_entry = tk.Entry(page2)
    resource_table_entry.grid(row=14, column=1)
    tk.Button(
        page2,
        text="Interact Resource Table",
        command=lambda: interact_resource_table(file_path.get(), resource_table_entry),
    ).grid(row=14, column=0)

    # Section Table
    tk.Label(page2, text="Section Table").grid(row=15, column=0)
    section_table_entry = tk.Entry(page2)
    section_table_entry.grid(row=15, column=1)
    tk.Button(
        page2,
        text="Interact Section Table",
        command=lambda: interact_section_table(file_path.get(), section_table_entry),
    ).grid(row=15, column=0)

    # Relocation Table
    tk.Label(page2, text="Relocation Table").grid(row=16, column=0)
    relocation_table_entry = tk.Entry(page2)
    relocation_table_entry.grid(row=16, column=1)
    tk.Button(
        page2,
        text="Interact Relocation Table",
        command=lambda: interact_relocation_table(file_path.get(), relocation_table_entry),
    ).grid(row=16, column=0)

    # Overlay
    tk.Label(page2, text="Overlay").grid(row=17, column=0)
    overlay_entry = tk.Entry(page2)
    overlay_entry.grid(row=17, column=1)
    tk.Button(
        page2,
        text="Interact Overlay",
        command=lambda: interact_overlay(file_path.get(), overlay_entry),
    ).grid(row=17, column=0)

    
    
    # Anti-Debugging Technique Identifier
    tk.Button(
        page2,
        text="Identify Anti-Debugging Techniques",
        command=lambda: display_results(identify_anti_debugging_techniques(file_path.get())),
    ).grid(row=1, column=3)  # Increase the row number by 1

    # Keygen
    tk.Button(
        page2,
        text="Open Keygen Window",
        command=open_keygen_window,  # Call the open_keygen_window function when the button is clicked
    ).grid(row=0, column=3)  # Place the "Open Keygen Window" button at row 0
    # Move 'Create Code Cave' and 'Interact TLS Callbacks' one row down

    # Create Code Cave
    code_cave_entry = tk.Entry(page2)
    code_cave_entry.grid(row=3, column=4)  # Change from row=1 to row=2
    tk.Button(
        page2,
        text="Create Code Cave",
        command=lambda: create_code_cave(file_path.get(), code_cave_entry),
    ).grid(row=3, column=3)  # Change from row=1 to row=2

    # TLS Callbacks Section
    tls_callbacks_entry = tk.Entry(page2)
    tls_callbacks_entry.grid(row=4, column=4)  # Change from row=2 to row=3
    tk.Button(
        page2,
        text="Interact TLS Callbacks",
        command=lambda: interact_tls_callbacks(file_path.get(), tls_callbacks_entry),
    ).grid(row=4, column=3)  # Change from row=2 to row=3

    # Add 'Find Code Cave' at the original position of 'Create Code Cave'
    find_code_cave_entry = tk.Entry(page2)
    find_code_cave_entry.grid(row=2, column=4)
    tk.Button(
        page2,
        text="Find Code Cave",
        command=lambda: find_code_cave(file_path.get(), find_code_cave_entry),
    ).grid(row=2, column=3)



    # Automatic Deobfuscation
    tk.Label(page2, text="Automatic Deobfuscation").grid(row=18, column=0, columnspan=2)
    tk.Button(
        page2,
        text="Execute",
        command=lambda: automatic_deobfuscation(file_path.get()),
    ).grid(row=18, column=2)

    # Binary Diffing
    tk.Label(page2, text="Binary Diffing - File 1").grid(row=19, column=0)
    binary_diffing_entry_1 = tk.Entry(page2)
    binary_diffing_entry_1.grid(row=19, column=1)
    tk.Button(
        page2,
        text="Browse",
        command=lambda: browse_files(binary_diffing_entry_1),
    ).grid(row=19, column=2)
    
    tk.Label(page2, text="Binary Diffing - File 2").grid(row=20, column=0)
    binary_diffing_entry_2 = tk.Entry(page2)
    binary_diffing_entry_2.grid(row=20, column=1)
    tk.Button(
        page2,
        text="Browse",
        command=lambda: browse_files(binary_diffing_entry_2),
    ).grid(row=20, column=2)
    
    tk.Button(
        page2,
        text="Compare",
        command=lambda: binary_diffing(
            binary_diffing_entry_1.get(), binary_diffing_entry_2.get()
        ),
    ).grid(row=21, column=0, columnspan=3)
    
    # remaining code


    tk.Button(
        page2,
        text="Binary Analysis Report",
        command=lambda: binary_analysis_report(file_path.get(), root),
    ).grid(row=22, column=2)

    
    oc = od.ObfuscationClassifier(od.PlatformType.ALL)

    def check_obfuscation(command):
        result = oc([command])
        return bool(result[0])  # returns True if obfuscated, False otherwise

    def detect():
        command = obfuscation_entry.get()
        if check_obfuscation(command):
            messagebox.showinfo('Obfuscation Detection', 'The command is obfuscated.')
        else:
            messagebox.showinfo('Obfuscation Detection', 'The command is not obfuscated.')

    
    
    # Obfuscation Detection
    tk.Label(page2, text="Obfuscation Detection - Command").grid(row=23, column=0)
    obfuscation_entry = tk.Entry(page2)
    obfuscation_entry.grid(row=23, column=1)
    tk.Button(
        page2,
        text="Detect Obfuscation",
        command=detect,
    ).grid(row=23, column=2)

    

    # Add a button to generate the expected reg file.
    tk.Button(
        page2,
        text="Expected Reg",
        command=lambda: generate_expected_reg(file_path_entry.get()),
    ).grid(row=24, column=2)


    # Raise page1 at the start
    raise_frame(page1)

    root.mainloop()

if __name__ == "__main__":
    main()
    

