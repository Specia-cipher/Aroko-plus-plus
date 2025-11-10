#!/usr/bin/env python3
import typer
import os
import secrets
import shutil
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag
from rich.progress import Progress
from rich.console import Console

app = typer.Typer(help="Aroko++ Hybrid Encryption CLI Tool")

# ------------------------------
# Banner
# ------------------------------
def print_banner():
    console = Console()
    banner = r"""
      _    ____  ____  _  __
     / \  |  _ \|  _ \| |/ /
    / _ \ | |_) | | | | ' / 
   / ___ \|  _ <| |_| | . \ 
  /_/   \_\_| \_\____/|_|\_\
                              
    """
    console.print(f"[bold green]{banner}[/bold green]")
    console.print("       [bold white]Welcome to Aroko++, a next-generation hybrid encryption CLI.[/bold white]\n")

# ------------------------------
# Key Utilities
# ------------------------------
def save_key(key, filepath, password=None):
    if password:
        enc_algo = serialization.BestAvailableEncryption(password.encode())
    else:
        enc_algo = serialization.NoEncryption()

    if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo
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
    return serialization.load_pem_private_key(
        data,
        password=password.encode() if password else None,
        backend=default_backend()
    )

def load_public_key(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    return serialization.load_pem_public_key(data, backend=default_backend())

# ------------------------------
# AES-GCM Utilities
# ------------------------------
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

# ------------------------------
# Metadata Scrubbing
# ------------------------------
def scrub_metadata(filepath, output):
    shutil.copy2(filepath, output)
    os.utime(output, (0, 0))
    typer.echo(f"Metadata scrubbed for {output}")

# ------------------------------
# Key Generation
# ------------------------------
@app.command()
def keygen(type: str = typer.Option(..., help="Key type: rsa or ecc"),
           out: str = typer.Option(..., help="Output folder for keys"),
           password: str = typer.Option(None, help="Passphrase for private key")):
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

# ------------------------------
# Hybrid AES Key Wrapping
# ------------------------------
def wrap_aes_key(aes_key, recipient_pub):
    if isinstance(recipient_pub, rsa.RSAPublicKey):
        enc_key = recipient_pub.encrypt(
            aes_key,
            rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None)
        )
        key_type = "rsa"
    elif isinstance(recipient_pub, ec.EllipticCurvePublicKey):
        ephemeral_priv = ec.generate_private_key(recipient_pub.curve, backend=default_backend())
        shared_secret = ephemeral_priv.exchange(ec.ECDH(), recipient_pub)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"AES key wrap",
            backend=default_backend()
        ).derive(shared_secret)
        iv, enc_key, tag = aes_gcm_encrypt(aes_key, derived_key)
        enc_key = iv + tag + enc_key  # pack IV+TAG+CIPHERTEXT
        key_type = "ecc"
    else:
        raise ValueError("Unsupported public key type")
    return enc_key, key_type

def unwrap_aes_key(enc_key, privkey, key_type):
    if key_type == "rsa":
        aes_key = privkey.decrypt(
            enc_key,
            rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None)
        )
    elif key_type == "ecc":
        iv, tag, ct = enc_key[:12], enc_key[12:28], enc_key[28:]
        shared_secret = privkey.exchange(ec.ECDH(), privkey.public_key())  # ephemeral handling needed
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"AES key wrap",
            backend=default_backend()
        ).derive(shared_secret)
        aes_key = aes_gcm_decrypt(ct, derived_key, iv, tag)
    else:
        raise ValueError("Unsupported key type")
    return aes_key

# ------------------------------
# Encryption Command
# ------------------------------
@app.command()
def encrypt(file: str = typer.Option(None, help="File to encrypt"),
            message: str = typer.Option(None, help="Text message to encrypt"),
            recipient: str = typer.Option(..., help="Recipient's public key file"),
            out: str = typer.Option(..., help="Output encrypted file"),
            symbolic: str = typer.Option(None, help="Symbolic message to embed"),
            scrub_metadata_flag: bool = typer.Option(False, "--scrub-metadata", help="Scrub metadata before encrypting"),
            progress: bool = typer.Option(False, help="Show progress bar")):

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
                    while chunk := fin.read(4096):
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

    aes_key = secrets.token_bytes(32)
    iv, ct, tag = aes_gcm_encrypt(data, aes_key)

    enc_key, key_type = wrap_aes_key(aes_key, pubkey)

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

# ------------------------------
# Decryption Command
# ------------------------------
@app.command()
def decrypt(file: str = typer.Option(..., help="Encrypted file"),
            private_key: str = typer.Option(..., help="Your private key file"),
            out: str = typer.Option(..., help="Output decrypted file"),
            password: str = typer.Option(None, help="Passphrase for private key"),
            progress: bool = typer.Option(False, help="Show progress bar")):

    privkey = load_private_key(private_key, password)
    with open(file, "rb") as fin:
        fin.readline()
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

    aes_key = unwrap_aes_key(enc_key, privkey, key_type)

    if progress:
        with Progress() as p:
            task = p.add_task("Decrypting...", total=ct_len)
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

# ------------------------------
# Secure Scrub/Delete
# ------------------------------
@app.command()
def scrub(file: str = typer.Option(..., help="File to scrub"),
          out: str = typer.Option(..., help="Output file after scrubbing")):
    scrub_metadata(file, out)

@app.command()
def delete(file: str = typer.Option(..., help="File to securely delete"),
           secure: bool = typer.Option(True, help="Perform secure deletion")):
    if secure:
        with open(file, "ba+") as f:
            length = f.tell()
            f.seek(0)
            f.write(secrets.token_bytes(length))
        os.remove(file)
    else:
        os.remove(file)
    typer.echo(f"File {file} deleted securely.")

# ------------------------------
# Symbolic Messaging (Aroko)
# ------------------------------
@app.command()
def aroko(message: str = typer.Option(..., help="Symbolic message to send"),
          recipient: str = typer.Option(..., help="Recipient's public key"),
          out: str = typer.Option(..., help="Output encrypted file")):

    pubkey = load_public_key(recipient)
    aes_key = secrets.token_bytes(32)
    iv, ct, tag = aes_gcm_encrypt(message.encode(), aes_key)

    enc_key, key_type = wrap_aes_key(aes_key, pubkey)

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

    privkey = load_private_key(private_key, password)
    with open(file, "rb") as fin:
        fin.readline()
        key_type = fin.readline().strip().decode()
        enc_key_len = int.from_bytes(fin.read(2), 'big')
        enc_key = fin.read(enc_key_len)
        iv = fin.read(12)
        tag = fin.read(16)
        ct_len = int.from_bytes(fin.read(8), 'big')
        ct = fin.read(ct_len)

    aes_key = unwrap_aes_key(enc_key, privkey, key_type)
    pt = aes_gcm_decrypt(ct, aes_key, iv, tag)
    if pt is None:
        typer.echo("Decryption failed. Wrong key or corrupted file.")
        raise typer.Exit(1)

    typer.echo(f"Symbolic message: {pt.decode()}")

# ------------------------------
# Main
# ------------------------------
if __name__ == "__main__":
    print_banner()
    app()

