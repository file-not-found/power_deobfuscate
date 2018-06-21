#!/usr/bin/env python2
import argparse
import re

r_chr = "\[char\](\d+)"
r_str = "('([^']*)')|(\"([^\"]*)\")"
r_pos = "\{(\d+)\}"
r_bstr = "(\(("+ r_str + ")\))|(" + r_str + ")"

r_format = "\(\s*[\"']((" + r_pos + ")+[\"']\s*)-f\s*(((" + r_str + ")\s*,)+\s*(" + r_str + "))\s*\)"
r_concat = "(\s*((" + r_str + ")\s*\+)+\s*(" + r_str + "))\s*"
r_replace = "(\((" + r_bstr + ")\s*-replace\s*(" + r_bstr + ")\s*,\s*(" + r_bstr + ")\s*\))"

r_no_newline = "(([^';]*'[^']*(;)[^']*'[^';]*)|([^\";]*\"[^\"]*(;)[^\"]*\"[^\";]*))(.*)$"
r_newline = "([^;]*);(.+)$"

def clean(string):
    if string is None:
        return ''
    else:
        return string

def deobfuscate_chr(text):
    # [char]97 -> 'a'
    matches = re.finditer(r_chr, text, re.IGNORECASE)
    for _, match in enumerate(matches):
        obfuscated = match.group()
        letter = int(match.groups()[0], 10)
        text = text.replace(obfuscated, "'" + chr(letter) + "'")
    return text

def deobfuscate_format(text):
    # ('{2}{1}{0}' -f "c","b","a") -> 'abc'
    matches = re.finditer(r_format, text, re.IGNORECASE)
    for _, match in enumerate(matches):
        obfuscated = match.group()
        positions = re.findall(r_pos, match.groups()[0], re.IGNORECASE)
        strings = re.findall(r_str, match.groups()[3], re.IGNORECASE)
        if len(positions) == len(strings):
            out = ""
            for p in positions:
               out += strings[int(p)][1]
            text = text.replace(obfuscated,"'"+out+"'")
    return text

def deobfuscate_concat(text):
    # 'a'+'b'+'c' -> 'abc'
    matches = re.finditer(r_concat, text, re.IGNORECASE)
    for _, match in enumerate(matches):
        obfuscated = match.group()
        strings = re.findall(r_str, match.groups()[0], re.IGNORECASE)
        out = ""
        for s in strings:
            out += s[1] + s[3]
        text = text.replace(obfuscated, "'"+out+"'")
    return text

def deobfuscate_replace(text):
    # ("aXcd" -replace "X","b") -> 'abcd'
    matches = re.finditer(r_replace, text, re.IGNORECASE)
    for _, match in enumerate(matches):
        obfuscated = match.group()
        target = clean(match.groups()[5]) + clean(match.groups()[10])
        old = clean(match.groups()[17]) + clean(match.groups()[22])
        new = clean(match.groups()[29]) + clean(match.groups()[34])
        out = target.replace(old, new)
        text = text.replace(obfuscated, "'"+out+"'")
    return text

def insert_newlines(text):
    remaining = text
    out = ""
    while ';' in remaining:
        # check for ';' in strings
        match = re.match(r_no_newline, remaining, re.S)
        if match is not None:
            if match.groups()[1] is not None:
                out += match.groups()[1]
            remaining = match.groups()[5]
        else:
            match = re.match(r_newline, remaining, re.S)
            if match is not None:
                line = match.groups()[0]
                remaining = match.groups()[1].lstrip()
                out += line + "\n"
        if remaining is None:
            remaining = ''
    text = out + remaining
    return text.rstrip()

def deobfuscate(text):
    backup = ""
    # loop while changes in text occur
    while backup != text:
        backup = text
        text = deobfuscate_chr(text)
        text = text.replace("`", "")
        text = deobfuscate_format(text)
        text = deobfuscate_concat(text)
        text = deobfuscate_replace(text)
    text = insert_newlines(text)
    return text

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Deobfuscate PowerShell Scripts')
    parser.add_argument("file", help="Input file")
    args = parser.parse_args()
    infile = args.file
    try:
        with open(infile, 'rb') as f_in:
            text = f_in.read()
    except:
        print("error reading file")
    text = deobfuscate(text)
    print(text)
