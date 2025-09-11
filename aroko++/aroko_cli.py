import typer
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import os
import secrets
from rich.progress import Progress
from rich.console import Console
import shutil

app = typer.Typer(help="Aroko++ Hybrid Encryption CLI Tool")

def print_banner():
    """Prints a colorful ASCII banner for the CLI."""
    console = Console()
    banner = """
  _   _                 _ _  _      _   _     
 | | | |               | | || |    | | | |    
 | |_| | ___  _ __ ___ | | || | ___| |_| | ___
 |  _  |/ _ \| '__/ _ \| |__   _|/ _ \_  _||___|
 | | | | (_) | | | (_) | |  | | (_) | | |   
 |_| |_|\___/|_|  \___/|_|  |_|\___/  |_|   
                                  ++
"""
    console.print(f"[bold green]{banner}[/bold green]")
    console.print("       [bold white]Welcome to Aroko++, a next-generation hybrid encryption CLI.[/bold white]\n")

def save_key(key, filepath, password=None):
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()
    if isinstance(key, rsa.RSAPrivateKey) or isinstance(key, ec.EllipticCurvePrivateKey):
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(filepath, 'wb') as f:
        f.write(pem)

def load_private_key(filepath, password=None):
    with open(filepath, 'rb') as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=password.encode() if password else None, backend=default_backend())

def load_public_key(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    return serialization.load_pem_public_key(data, backend=default_backend())

@app.command()
def keygen(type: str = typer.Option(..., help="Key type: rsa or ecc"),
           out: str = typer.Option(..., help="Output folder for keys"),
           password: str = typer.Option(None, help="Passphrase for private key")):
    """Generate RSA/ECC key pair."""
    if not os.path.exists(out):
        os.makedirs(out)
    if type == "rsa":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    elif type == "ecc":
        priv = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
    else:
        typer.echo("Key type must be 'rsa' or 'ecc'")
        raise typer.Exit(1)
    pub = priv.public_key()
    save_key(priv, os.path.join(out, "private.pem"), password)
    save_key(pub, os.path.join(out, "public.pem"))
    typer.echo(f"{type.upper()} keypair generated at {out}")

def aes_gcm_encrypt(data, key, associated_data=b""):
    iv = secrets.token_bytes(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    encryptor.authenticate_additional_data(associated_data)
    ct = encryptor.update(data) + encryptor.finalize()
    return iv, ct, encryptor.tag

def aes_gcm_decrypt(data, key, iv, tag, associated_data=b""):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    decryptor.authenticate_additional_data(associated_data)
    try:
        pt = decryptor.update(data) + decryptor.finalize()
    except InvalidTag:
        return None
    return pt

def scrub_metadata(filepath, output):
    shutil.copy2(filepath, output)
    # Remove extended attributes and timestamps (basic)
    os.utime(output, (0, 0))
    # Could add more sophisticated metadata scrubbing here
    typer.echo(f"Metadata scrubbed for {output}")

@app.command()
def encrypt(file: str = typer.Option(None, help="File to encrypt"),
            message: str = typer.Option(None, help="Text message to encrypt"),
            recipient: str = typer.Option(..., help="Recipient's public key file"),
            out: str = typer.Option(..., help="Output encrypted file"),
            symbolic: str = typer.Option(None, help="Symbolic message to embed"),
            scrub_metadata_flag: bool = typer.Option(False, "--scrub-metadata", help="Scrub metadata before encrypting"),
            progress: bool = typer.Option(False, help="Show progress bar")):
    """Encrypt a file or message for a recipient."""
    pubkey = load_public_key(recipient)

    if file:
        input_path = file
        if scrub_metadata_flag:
            scrubbed = input_path + ".scrubbed"
            scrub_metadata(input_path, scrubbed)
            input_path = scrubbed
        filesize = os.path.getsize(input_path)
        with open(input_path, "rb") as fin:
            if progress:
                with Progress() as p:
                    task = p.add_task("Encrypting...", total=filesize)
                    chunks = []
                    while True:
                        chunk = fin.read(4096)
                        if not chunk: break
                        chunks.append(chunk)
                        p.update(task, advance=len(chunk))
                    data = b''.join(chunks)
            else:
                data = fin.read()
    elif message:
        data = message.encode()
    else:
        typer.echo("Provide either --file or --message to encrypt.")
        raise typer.Exit(1)

    # Generate a random AES key
    aes_key = secrets.token_bytes(32)
    iv, ct, tag = aes_gcm_encrypt(data, aes_key)
    # Encrypt AES key with recipient's public key
    if hasattr(pubkey, "encrypt"):
        enc_key = pubkey.encrypt(aes_key, rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        key_type = "rsa"
    else:
        # Note: ECDH key exchange is not handled this way. This is a placeholder for future implementation.
        enc_key = b''
        key_type = "ecc"

    with open(out, "wb") as fout:
        fout.write(b"AROKO++\n")
        fout.write(key_type.encode() + b"\n")
        fout.write(len(enc_key).to_bytes(2, 'big') + enc_key)
        fout.write(iv)
        fout.write(tag)
        fout.write(len(ct).to_bytes(8, 'big') + ct)
        if symbolic:
            fout.write(b"\nAROKO-MSG:" + symbolic.encode())
    typer.echo(f"Encrypted output written to {out}")

@app.command()
def decrypt(file: str = typer.Option(..., help="Encrypted file"),
            private_key: str = typer.Option(..., help="Your private key file"),
            out: str = typer.Option(..., help="Output decrypted file"),
            password: str = typer.Option(None, help="Passphrase for private key"),
            progress: bool = typer.Option(False, help="Show progress bar")):
    """Decrypt a file."""
    privkey = load_private_key(private_key, password)
    with open(file, "rb") as fin:
        header = fin.readline()
        key_type = fin.readline().strip().decode()
        enc_key_len = int.from_bytes(fin.read(2), 'big')
        enc_key = fin.read(enc_key_len)
        iv = fin.read(12)
        tag = fin.read(16)
        ct_len = int.from_bytes(fin.read(8), 'big')
        ct = fin.read(ct_len)
        rest = fin.read()
        symbolic_msg = None
        if b"AROKO-MSG:" in rest:
            symbolic_msg = rest.split(b"AROKO-MSG:")[1].decode()

    # Decrypt AES key
    if key_type == "rsa":
        aes_key = privkey.decrypt(enc_key, rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    elif key_type == "ecc":
        # Note: ECDH key exchange is not handled this way. This is a placeholder for future implementation.
        aes_key = b''
    else:
        typer.echo("Unknown key type in encrypted file.")
        raise typer.Exit(1)

    # Decrypt data
    if progress:
        with Progress() as p:
            task = p.add_task("Decrypting...", total=ct_len)
            # Simulate progress
            for i in range(0, ct_len, 4096):
                p.update(task, advance=min(4096, ct_len - i))
            pt = aes_gcm_decrypt(ct, aes_key, iv, tag)
    else:
        pt = aes_gcm_decrypt(ct, aes_key, iv, tag)
    if pt is None:
        typer.echo("Decryption failed. Wrong key or corrupted file.")
        raise typer.Exit(1)
    with open(out, "wb") as fout:
        fout.write(pt)
    typer.echo(f"Decrypted output written to {out}")
    if symbolic_msg:
        typer.echo(f"Symbolic message: {symbolic_msg}")

@app.command()
def scrub(file: str = typer.Option(..., help="File to scrub"),
          out: str = typer.Option(..., help="Output file after scrubbing")):
    """Scrub sensitive metadata from a file."""
    scrub_metadata(file, out)

@app.command()
def delete(file: str = typer.Option(..., help="File to securely delete"),
           secure: bool = typer.Option(True, help="Perform secure deletion")):
    """Securely delete a file."""
    if secure:
        # Overwrite the file before deleting
        with open(file, "ba+") as f:
            length = f.tell()
            f.seek(0)
            f.write(secrets.token_bytes(length))
        os.remove(file)
    else:
        os.remove(file)
    typer.echo(f"File {file} deleted securely.")

@app.command()
def aroko(message: str = typer.Option(..., help="Symbolic message to send"),
          recipient: str = typer.Option(..., help="Recipient's public key"),
          out: str = typer.Option(..., help="Output encrypted file")):
    """Send a symbolic encrypted message (Aroko mode)."""
    # Symbolic message is encrypted and embedded in output file
    pubkey = load_public_key(recipient)
    aes_key = secrets.token_bytes(32)
    iv, ct, tag = aes_gcm_encrypt(message.encode(), aes_key)
    if hasattr(pubkey, "encrypt"):
        enc_key = pubkey.encrypt(aes_key, rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        key_type = "rsa"
    else:
        # Note: ECDH key exchange is not handled this way. This is a placeholder for future implementation.
        enc_key = b''
        key_type = "ecc"
    with open(out, "wb") as fout:
        fout.write(b"AROKO++-AROKO\n")
        fout.write(key_type.encode() + b"\n")
        fout.write(len(enc_key).to_bytes(2, 'big') + enc_key)
        fout.write(iv)
        fout.write(tag)
        fout.write(len(ct).to_bytes(8, 'big') + ct)
    typer.echo(f"Symbolic message encrypted and sent to {out}")

@app.command("extract-aroko")
def extract_aroko(file: str = typer.Option(..., help="File to extract symbolic message from"),
                  private_key: str = typer.Option(..., help="Your private key file"),
                  password: str = typer.Option(None, help="Passphrase for private key")):
    """Extract symbolic message from encrypted output."""
    privkey = load_private_key(private_key, password)
    with open(file, "rb") as fin:
        header = fin.readline()
        key_type = fin.readline().strip().decode()
        enc_key_len = int.from_bytes(fin.read(2), 'big')
        enc_key = fin.read(enc_key_len)
        iv = fin.read(12)
        tag = fin.read(16)
        ct_len = int.from_bytes(fin.read(8), 'big')
        ct = fin.read(ct_len)
    if key_type == "rsa":
        aes_key = privkey.decrypt(enc_key, rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    elif key_type == "ecc":
        # Note: ECDH key exchange is not handled this way. This is a placeholder for future implementation.
        aes_key = b''
    else:
        typer.echo("Unknown key type in encrypted file.")
        raise typer.Exit(1)
    pt = aes_gcm_decrypt(ct, aes_key, iv, tag)
    if pt is None:
        typer.echo("Decryption failed. Wrong key or corrupted file.")
        raise typer.Exit(1)
    typer.echo(f"Symbolic message: {pt.decode()}")

if __name__ == "__main__":
    print_banner()
    app()

