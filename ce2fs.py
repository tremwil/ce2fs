from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import xml.etree.ElementTree as et
else:
    import lxml.etree as et

import lxml.etree

import io
import os
import re
import sys
import shutil
import random
import zlib
import argparse

from os.path import join, isdir, isfile

CT_MAX_ID: int = 2**63 - 1
BAD_FILENAME_RE: re.Pattern[str] = re.compile(r'[\x00-\x1F<>:"/\\|?*]')
ORDER_TAG: str = "x-ce2fs-child-order"


B85_ALPHABET: bytes = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%()*+,-./:;=?@[]^_{}'
B85_LOOKUP = bytearray(256)
for i, c in enumerate(B85_ALPHABET): B85_LOOKUP[c] = i


def b85decode(encoded: str) -> bytes:
    encoded: bytes = encoded.encode()
    decoded = io.BytesIO()
    for i in range(0, len(encoded), 5):
        block = encoded[i:i+5]
        
        k = 0 # Convert 5-digit base85 number to integer
        for c in block.ljust(5, b'}'): 
            k = B85_LOOKUP[c] + k * 85

        decoded.write(k.to_bytes(4, 'big')[:len(block)-1])

    return decoded.getvalue()


def b85encode(blob: bytes) -> str:
    encoded = io.BytesIO()
    b85_buff = bytearray(5)
    for i in range(0, len(blob), 4):
        block = blob[i:i+4]

        # Convert 4-byte be u32 to 5-digit base85 number
        k = int.from_bytes(block.ljust(4, b'\0'), 'big')
        for i in range(4, -1, -1):
            k, r = divmod(k, 85)
            b85_buff[i] = B85_ALPHABET[r]

        encoded.write(b85_buff[:len(block)+1])

    return encoded.getvalue().decode()


def elem_to_file(elem: et.Element, path: str, mode: str = "x", xml_decl: bool = False):
    # We use text mode and manually create the XML decl, because
    # etree.tostring in binary mode doesn't output system-compliant line breaks
    with open(path, mode, encoding="utf-8") as f:
        if xml_decl:
            f.write('<?xml version="1.0" encoding="utf-8"?>\n')
        f.write(lxml.etree.tostring(elem, pretty_print=True, encoding=str))


def make_valid_filename(s: str):
    s = re.sub(BAD_FILENAME_RE, "", s).rstrip(" .").removesuffix(".xml").removesuffix(".cea")
    return s or None


class Unpacker:
    def __init__(self, strip: list[str] = ["UserdefinedSymbols", "Hotkeys"]):
        self.strip_tags = strip

    def strip(self, elem: et.Element):
        for tag in self.strip_tags:
            for c in elem.findall(tag):
                elem.remove(c)

    def on_files(self, files: et.Element, path: str):
        path = join(path, files.tag)
        os.makedirs(path, exist_ok=True)

        for file in files:
            compressed = (
                b85decode(file.text) if file.get("Encoding") == "Ascii85" 
                else bytes.fromhex(file.text)
            )
            dc = zlib.decompressobj(-15)
            size = int.from_bytes(dc.decompress(compressed, 4), "little")
            decompressed = dc.decompress(dc.unconsumed_tail, size)

            fpath = join(path, file.tag)
            file.text, file.tag = "", "File"
            elem_to_file(file, fpath + ".xml")

            with open(fpath, "xb") as f:
                f.write(decompressed)

    def on_cheat_entries(self, entries: et.Element, path: str) -> et.Element:
        child_order = et.Element("x-ce2fs-child-order")
        name_use_counts = {".cea": 1, ".xml": 1} # reserved names
        for elem in entries:
            if elem.tag != "CheatEntry":
                raise ValueError(f"Unexpected tag: {elem.tag} in CheatEntries list")
            if (id_elem := elem.find("ID")) is not None:
                child_order.append(et.Element("id", id=id_elem.text))
            self.on_cheat_entry(elem, path, name_use_counts)
        return child_order

    def on_cheat_entry(self, entry: et.Element, path: str, name_use_counts: dict[str, int]):
        fname: str | None = None
        if (desc := entry.find("Description")) is not None:
            fname = make_valid_filename(desc.text.strip(' "'))
        if fname is None and (id := entry.find("ID")) is not None:
            fname = id.text
        if fname is None:
            raise ValueError(f"Cannot generate file name from CheatEntry")
        
        count = name_use_counts.get(fname, 0) + 1
        name_use_counts[fname] = count
        if count > 1: fname += f" {count}"

        if (children := entry.find("CheatEntries")) is not None:
            path = join(path, fname)
            os.makedirs(path)
            entry.append(self.on_cheat_entries(children, path))
            entry.remove(children)
            fname = ""

        if (aa := entry.find("AssemblerScript")) is not None:
            with open(join(path, fname + ".cea"), "x") as f:
                f.write(aa.text)
            entry.remove(aa)
        
        self.strip(entry)
        elem_to_file(entry, join(path, fname + ".xml"))

    def on_structures(self, structs: et.Element, path: str):
        os.makedirs(path, exist_ok=True)
        for i, struct in enumerate(structs):
            fname = None
            if (name := structs.find("Name")) is not None:
                fname = make_valid_filename(name)
            if fname is None:
                fname = "struct%04d" % i
            elem_to_file(struct, join(path, fname + ".xml"))

    def on_cheat_table(self, ct: et.Element, path: str):
        path = join(path, ct.tag)
        shutil.rmtree(os.path.abspath(path), onexc=lambda *a: None)
        os.makedirs(path, exist_ok=True)

        self.strip(ct)
        if (files := ct.find("Files")) is not None:
            self.on_files(files, path)
            ct.remove(files)

        if (entries := ct.find("CheatEntries")) is not None:
            epath = join(path, "CheatEntries")
            os.makedirs(epath, exist_ok=True)

            ce = et.Element("CheatEntry")
            ce.append(self.on_cheat_entries(entries, epath))
            elem_to_file(ce, join(epath, ".xml"))
            ct.remove(entries)
        
        if (structs := ct.find("Structures")) is not None:
            self.on_cheat_table(structs, join(path, "Structures"))
            ct.remove(structs)

        elem_to_file(ct, join(path, ".xml"))

    def unpack_table(self, table_path: str, extraction_dir: str):
        table_path = os.path.abspath(table_path)
        extraction_dir = os.path.abspath(extraction_dir)
        tree = et.parse(table_path, et.XMLParser(remove_blank_text=True))
        root = tree.getroot()
        assert root.tag == "CheatTable", "Input file is not a Cheat Engine table"
        self.on_cheat_table(root, extraction_dir)


class Packer:
    def __init__(self, fixup_xml: bool = False):
        self.used_ids: set[int] = set()
        self.fixup_xml = fixup_xml
        self.parser: et.XMLParser = et.XMLParser(remove_blank_text=True, encoding="utf-8")

    def collect_ids(self, path: str):
        self.used_ids = set()
        for root, _, files in os.walk(path):
            for xml_file in (f for f in files if f.endswith(".xml")):
                file_root = et.parse(join(root, xml_file), self.parser).getroot()
                if file_root.tag == "CheatEntry" and (id_tag := file_root.find("ID")) is not None:
                    entry_id = int(id_tag.text)
                    if entry_id in self.used_ids: 
                        raise ValueError(f"Duplicate IDs: {entry_id}")
                    self.used_ids.add(entry_id)

    def get_id(self):
        while (i := random.randint(0, CT_MAX_ID)) in self.used_ids: pass
        self.used_ids.add(i)
        return i
    
    def get_or_gen_xml(
        self, 
        path: str, 
        expected_tag: str, 
        *, 
        has_id: bool = False, 
        has_description: bool = False,
        has_script: bool = False,
        has_sub_entries: bool = False,
    ) -> et.Element:
        base: et.Element = (
            et.parse(path, self.parser).getroot() if isfile(path)
            else et.Element(expected_tag)
        )
        if base.tag != expected_tag:
            raise ValueError(f"Unexpected tag for XML root element: {base.tag}")
        if has_id and base.find("ID") is None:
            et.SubElement(base, "ID").text = str(self.get_id())
        if has_description and base.find("Description") is None:
            head, tail = os.path.split(path)
            et.SubElement(base, "Description").text = (
                os.path.basename(head) if tail == ".xml" else tail.removesuffix(".xml")
            )
        
        if (has_sub_entries 
            and base.find("VariableType") is None 
            and base.find("GroupHeader") is None
            and base.find("Options") is None
        ):
            et.SubElement(base, "Options", moHideChildren="1")

        if base.find("VariableType") is None:
            if has_script:
                et.SubElement(base, "VariableType").text = "Auto Assembler Script"
            elif has_sub_entries and base.find("GroupHeader") is None:
                et.SubElement(base, "GroupHeader").text = "1"
    
        return base

    def pack_table(self, path: str, ct_save_path: str | None):
        path = os.path.abspath(path)

        self.collect_ids(path)
        root = self.get_or_gen_xml(join(path, ".xml"), "CheatTable")

        if isdir(files := join(path, "Files")):
            root.append(self.on_files(files))
        if isdir(entries := join(path, "CheatEntries")):
            root.append(self.on_cheat_entry_folder(entries, isroot=True).find("CheatEntries"))
        if isdir(structs := join(path, "Structures")):
            root.append(self.on_structures(structs))
        
        if ct_save_path:
            elem_to_file(root, ct_save_path, "w", xml_decl=True)
    
    def on_files(self, path: str) -> et.Element:
        files = et.Element("Files")
        for fname in os.listdir(path):
            fpath = join(path, fname)
            # Edge case -- File ends with .xml, but has no meta -> interpret as metadata file
            if fpath.endswith(".xml") and not isfile(fpath + ".xml"):
                continue

            with open(fpath, "rb") as f:
                raw_data = f.read()
            
            c = zlib.compressobj(level=9, wbits=-15)

            mstream = io.BytesIO()
            mstream.write(c.compress(len(raw_data).to_bytes(4, 'little')))
            mstream.write(c.compress(raw_data))
            mstream.write(c.flush(zlib.Z_FINISH))
            compressed = mstream.getvalue()

            file = self.get_or_gen_xml(fpath + ".xml", "File")
            file.set("Encoding", file.get("Encoding") or "Ascii85")

            if self.fixup_xml:
                elem_to_file(file, fpath + ".xml", "w")

            file.tag = fname
            file.text = b85encode(compressed) if file.get("Encoding") == "Ascii85" else compressed.hex()
            files.append(file)

        return files
    
    def on_structures(self, path: str) -> et.Element:
        structs = et.Element("Structures")
        for fname in os.listdir(path):
            if not fname.endswith(".xml"): continue
            structs.append(et.parse(join(path, fname), self.parser).getroot())
        return structs

    def on_cheat_entry_folder(self, path: str, isroot: bool = False) -> et.Element:
        entry: et.Element
        if isfile(join(path, ".cea")):
            entry = self.on_cea_file(join(path, ".cea"))
        else:
            entry = self.get_or_gen_xml(
                join(path, ".xml"), "CheatEntry", has_id=not isroot, has_sub_entries=not isroot
            )
        
        children_by_id: dict[int, et.Element] = dict()
        for fname in os.listdir(path):
            fpath = join(path, fname)
            child: et.Element
            if isdir(fpath):
                child = self.on_cheat_entry_folder(fpath)
            elif fname == ".cea" or fname == ".xml":
                continue
            elif fname.endswith(".cea"):
                child = self.on_cea_file(fpath)
            elif fname.endswith(".xml") and not isfile(fpath[:-4] + ".cea"):
                child = self.get_or_gen_xml(fpath, "CheatEntry", has_id=True)
                if self.fixup_xml:
                    elem_to_file(fpath, child)
            else:
                continue

            children_by_id[int(child.find("ID").text)] = child
        
        if (ordering := entry.find(ORDER_TAG)) is None:
            ordering = et.SubElement(entry, ORDER_TAG)
            ordering.extend(et.Element("id", id=str(k)) for k in children_by_id)

        if self.fixup_xml:
            # Pretty jank but eh
            script: et.Element | None = None
            for i, c in enumerate(entry):
                if c.tag == "AssemblerScript":
                    script = c
                    entry.remove(c)
                    break
            elem_to_file(join(path, ".xml"), entry)
            if script is not None:
                entry.insert(i, script)

        entry.remove(ordering)
        entries = et.SubElement(entry, "CheatEntries")
        for id_tag in ordering:
            entries.append(children_by_id[int(id_tag.get("id"))])

        return entry

    def on_cea_file(self, path: str, has_sub_entries: bool = False) -> et.Element:
        xml_path = path[:-4] + ".xml"
        script = self.get_or_gen_xml(
            xml_path, "CheatEntry", has_id=True, has_sub_entries=has_sub_entries, has_script=True
        )
        if self.fixup_xml and os.path.basename(path) != ".cea":
            elem_to_file(xml_path, script)

        if (s := script.find("AssemblerScript")) is None:
            s = et.SubElement(script, "AssemblerScript")

        with open(path, "r") as f:
            s.text = f.read()
        
        return script

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog="ce2fs",
        description="converts Cheat Engine (.CT) tables to and from file system structures",
        add_help=True,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-i", "--input", 
        dest="input",
        required=True,
        help="input .CT file path (when unpacking) or an unpacked table (CheatEngine) folder (when packing)"
    )
    parser.add_argument(
        "-o", "--output",
        dest="output", 
        help="output folder in which to place the unpacked table (when unpacking), or .CT file path (when packing)"
    )
    parser.add_argument(
        "-s", "--strip",
        dest="strip",
        nargs="*",
        default=["UserdefinedSymbols", "Hotkeys"],
        help="list of Cheat Engine XML tags to exclude during unpacking"
    )
    parser.add_argument(
        "-f", "--fixup",
        dest="fixup",
        type=bool,
        default=False,
        help="if true, will generate missing XML files/tags during packing"
    )

    args = parser.parse_args()
    if not os.path.exists(args.input):
        parser.error(f"Input path ({args.input}) does not point to a valid file or folder")

    if isfile(args.input):
        if args.output is None:
            parser.error(f"Missing required argument for unpacking: -o/--output")
        if not isdir(args.output):
            parser.error(f"Output path ({args.output}) does not point to a valid directory")
        Unpacker(strip=args.strip).unpack_table(args.input, args.output)
    else:
        if args.output is None and not args.fixup:
            parser.error(f"Unpacking without providing an output CT file will do nothing unless -f/--fixup is provided")
        Packer(fixup_xml=args.fixup).pack_table(args.input, args.output)