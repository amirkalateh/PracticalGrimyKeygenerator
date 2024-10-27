{pkgs}: {
  deps = [
    pkgs.mailutils
    pkgs.imagemagick
    pkgs.rustc
    pkgs.pkg-config
    pkgs.openssl
    pkgs.libxcrypt
    pkgs.libiconv
    pkgs.cargo
    pkgs.glibcLocales
  ];
}
