import typer

app = typer.Typer(help="Aroko++: Hybrid Encryption CLI Tool")

@app.command()
def keygen(
    type: str = typer.Option(..., help="Key type: rsa or ecc"),
    out: str = typer.Option(..., help="Output folder for the key pair"),
    password: str = typer.Option(None, help="Optional passphrase for the key")
):
    """Generate RSA/ECC key pair."""
    typer.echo(f"Key generation: type={type}, out={out}, password={'***' if password else '(none)'}")


@app.command()
def encrypt(
    file: str = typer.Option(None, help="File to encrypt"),
    message: str = typer.Option(None, help="Text message to encrypt"),
    recipient: str = typer.Option(..., help="Recipient's public key file"),
    out: str = typer.Option(..., help="Output encrypted file"),
    symbolic: str = typer.Option(None, help="Symbolic Aroko message to embed"),
    scrub_metadata: bool = typer.Option(False, help="Scrub sensitive metadata before encrypting"),
    progress: bool = typer.Option(False, help="Show progress bar")
):
    """Encrypt a file or message for a recipient."""
    typer.echo(f"Encrypt: file={file}, message={message}, recipient={recipient}, out={out}, symbolic={symbolic}, scrub_metadata={scrub_metadata}, progress={progress}")


@app.command()
def decrypt(
    file: str = typer.Option(None, help="File to decrypt"),
    message: str = typer.Option(None, help="Encrypted message file"),
    private_key: str = typer.Option(..., help="Private key file"),
    out: str = typer.Option(None, help="Output decrypted file"),
    password: str = typer.Option(None, help="Passphrase for the private key"),
    progress: bool = typer.Option(False, help="Show progress bar")
):
    """Decrypt a file or message."""
    typer.echo(f"Decrypt: file={file}, message={message}, private_key={private_key}, out={out}, password={'***' if password else '(none)'}, progress={progress}")


@app.command()
def scrub(
    file: str = typer.Option(..., help="File to scrub"),
    out: str = typer.Option(..., help="Output file after scrubbing"),
):
    """Scrub sensitive metadata from a file."""
    typer.echo(f"Scrub: file={file}, out={out}")


@app.command()
def delete(
    file: str = typer.Option(..., help="File to securely delete"),
    secure: bool = typer.Option(True, help="Perform secure deletion")
):
    """Securely delete a file."""
    typer.echo(f"Delete: file={file}, secure={secure}")


@app.command()
def aroko(
    message: str = typer.Option(..., help="Symbolic message to send"),
    recipient: str = typer.Option(..., help="Recipient's public key"),
    out: str = typer.Option(..., help="Output encrypted file")
):
    """Send a symbolic encrypted message (Aroko mode)."""
    typer.echo(f"Aroko: message={message}, recipient={recipient}, out={out}")


@app.command("extract-aroko")
def extract_aroko(
    file: str = typer.Option(..., help="File to extract symbolic message from")
):
    """Extract symbolic message from encrypted output."""
    typer.echo(f"Extract Aroko: file={file}")


if __name__ == "__main__":
    app()
