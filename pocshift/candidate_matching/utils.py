import hashlib

def hashString(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def hashFile(file_path):
    with open(file_path, 'r') as f:
        s = f.read()
    return hashString(s)
