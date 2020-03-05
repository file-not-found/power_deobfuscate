#!/usr/bin/env python2
import argparse
import re

regex_chr = "\[char\](\d+)"
regex_quotestr = "('([^']*)')|(\"([^\"]*)\")" # 'string' or "string" (match = +2)
regex_pos = "\{(\d+)\}" # {123} (match = +1)

regex_bracketstr = "\(("+ regex_quotestr + ")\)" # ('string')
regex_anystr = "("+ regex_bracketstr + ")|(" + regex_quotestr + ")" # ('string') or 'string' (match = +2)

regex_format = "\(\s*[\"']((" + regex_pos + ")+[\"']\s*)-f\s*(((" + regex_quotestr + ")\s*,)+\s*(" + regex_quotestr + "))\s*\)"
regex_concat = "(\s*((" + regex_quotestr + ")\s*\+)+\s*(" + regex_quotestr + "))\s*"
regex_replace = "(\((" + regex_anystr + ")\s*-replace\s*(" + regex_anystr + ")\s*,\s*(" + regex_anystr + ")\s*\))" # ("asdf" -replace "as", "AS")
regex_invoke = "(\.\s*['\"]?invoke['\"]?)?"
regex_replace2 = "(\((" + regex_anystr + ").\s*['\"]?replace['\"]?" + regex_invoke + "\s*\(\s*(" + regex_anystr + ")\s*,\s*(" + regex_anystr + ")\s*\)\))"

r_variable_decl = "[.&]\(?('set'|'set-item'|'si'|'set-variable'|'sv')\)?\s*\(?'(variable:)?([^']*)'\)?\s*\(\s*([^\)\s]*)\s*\)\s*;"
#r_variable_decl2 = "\$\{([^\"']+)\}\s*=\s*([^\s]+)\s*;" # for ${asdf}='text'; to many false positives
r_variable_deref = "\$\{(VARIABLE_NAME)\}"  # placeholder gets replaced
r_variable_deref_dir = "\(\s*[.&]\(?'(dir|ls|get-variable|gv|gi)'\)?\s*\(?'(variable:)?VARIABLE_NAME'(\s*\)){0,2}\.\"value\""

def clean(string):
    if string is None:
        return ''
    else:
        return string

def deobfuscate_chr(text):
    # [char]97 -> 'a'
    matches = re.finditer(regex_chr, text, re.IGNORECASE)
    for _, match in enumerate(matches):
        obfuscated = match.group()
        letter = int(match.groups()[0], 10)
        text = text.replace(obfuscated, "'" + chr(letter) + "'")
    return text

def deobfuscate_brackets(text):
    # ('a') -> 'a'
    matches = re.finditer(regex_bracketstr, text, re.IGNORECASE)
    for _, match in enumerate(matches):
        obfuscated = match.group()
        string = match.groups()[0]
        text = text.replace(obfuscated, string)
    return text

def deobfuscate_format(text):
    # ('{2}{1}{0}' -f "c","b","a") -> 'abc'
    matches = re.finditer(regex_format, text, re.IGNORECASE)
    for _, match in enumerate(matches):
        obfuscated = match.group()
        positions = re.findall(regex_pos, match.groups()[0], re.IGNORECASE)
        strings = re.findall(regex_quotestr, match.groups()[3], re.IGNORECASE)
        if len(positions) == len(strings):
            out = ""
            for p in positions:
               out += strings[int(p)][1]
            text = text.replace(obfuscated,"'"+out+"'")
    return text

def deobfuscate_concat(text):
    # 'a'+'b'+'c' -> 'abc'
    matches = re.finditer(regex_concat, text, re.IGNORECASE)
    for _, match in enumerate(matches):
        obfuscated = match.group()
        strings = re.findall(regex_quotestr, match.groups()[0], re.IGNORECASE)
        out = ""
        for s in strings:
            out += s[1] + s[3]
        text = text.replace(obfuscated, "'"+out+"'")
    return text

def deobfuscate_replace(text):
    # ("aXcd" -replace "X","b") -> 'abcd'
    matches = re.finditer(regex_replace, text, re.IGNORECASE)
    for _, match in enumerate(matches):
        obfuscated = match.group()

        target = clean(match.groups()[5]) + clean(match.groups()[10])
        old = clean(match.groups()[17]) + clean(match.groups()[22])
        new = clean(match.groups()[29]) + clean(match.groups()[34])
        out = target.replace(old, new)
        text = text.replace(obfuscated, "'"+out+"'")
    return text

def deobfuscate_replace2(text):
    # ("aXcd".replace("X","b")) -> 'abcd'
    matches = re.finditer(regex_replace2, text, re.IGNORECASE)
    for _, match in enumerate(matches):
        obfuscated = match.group()

        target = clean(match.groups()[5]) + clean(match.groups()[10])
        old = clean(match.groups()[18]) + clean(match.groups()[23])
        new = clean(match.groups()[30]) + clean(match.groups()[35])
        out = target.replace(old, new)
        text = text.replace(obfuscated, "'"+out+"'")
    return text

def deobfuscate_variable(text):
    # .'set' ('Variable:a') ('abc')
    matches = re.finditer(r_variable_decl, text, re.IGNORECASE)
    for _, match in enumerate(matches):
        obfuscated = match.group()

        # replace all references
        name = match.groups()[0]
        value = match.groups()[1]
        text = replace_variable(text, name, value)
        if text.count(obfuscated) == 1:
            # remove declaration
            # this can be a problem if not all references are replaced
            text = text.replace(obfuscated, "").strip()

    return text

def replace_variable(text, variable, value):
    # ${VARIABLE_NAME} -> 'abc'
    matches = re.finditer(r_variable_deref.replace('VARIABLE_NAME',variable), text, re.IGNORECASE)
    for _, match in enumerate(matches):
        obfuscated = match.group()
        text = text.replace(obfuscated,value)

    # (&'dir' 'Variable:VARIABLE_NAME)."Value" -> 'abc'
    matches = re.finditer(r_variable_deref_dir.replace('VARIABLE_NAME',variable), text, re.IGNORECASE)
    for _, match in enumerate(matches):
        obfuscated = match.group()
        text = text.replace(obfuscated,value)
    return text 


# try to find and replace characters outside of strings
def replace_nonstring(text, search, replace):
    str_seperators = '\'"'  # possible string delimiter
    current_string = None   # store if we are inside a string and which delimiter is used
    for pos in range(len(text)):
        if current_string != None:
            # inside a string
            if text[pos] == current_string:
                current_string = None
        elif text[pos] == search:
            # not inside a string, so check for character
            line = text[:pos] + replace
            remaining = text[pos+1:]
            return line, remaining
        elif text[pos] in str_seperators:
            # new string delimiter found
            current_string = text[pos]
    return text, ''  # character not found

# insert newlines after semicolons
def insert_newlines(text):
    remaining = text
    out = ''
    while remaining != '':
        line, remaining = replace_nonstring(remaining, ';', ';\n')
        if len(line) > 0:
            out += line
    text = out
    return text.rstrip()

def deobfuscate(text):
    backup = ""
    # loop while changes in text occur
    while backup != text:
        backup = text
        text = deobfuscate_chr(text)
        text = text.replace("`", "")
        text = deobfuscate_format(text)
        text = deobfuscate_brackets(text)
        text = deobfuscate_concat(text)
        text = deobfuscate_replace(text)
        text = deobfuscate_replace2(text)
        text = deobfuscate_variable(text)
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
    text = text.replace('\n', '').replace('\r','')
    text = deobfuscate(text)
    print(text)
