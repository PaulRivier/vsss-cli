# vsss-cli

CLI wrapper around [`vsss-rs`](https://github.com/mikelodder7/vsss-rs),
with some restrictions :
- [`shamir scheme`](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) only
- bytes array secret only using [`GF(256)`](https://en.wikipedia.org/wiki/Finite_field_arithmetic)


## How to use

See `vsss-cli help`.

Example :

    # Split MY_SECRET_FILE into 5 shares with threshold=3
    vsss-cli split -t3 -n5 -s MY_SECRET_FILE -d parts/ 

    # Combine back shares from directory "parts" into MY_REVEALED_SECRET
    vsss-cli combine -d parts/ -o MY_REVEALED_SECRET



## Static build (musl, Linux)

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Disclaimer

Use at your own risk. Author is not an expert.

Also, since vsss-rs produce simple binary `(x,F(x) over bytestring)`
output without any meta information about its format, it is certainly
very wise to keep a copy of the software you used to produce the share
in case the format change in the future. AFAIK, there is unfortunately
no widespread format standard for SSS shares, so it will always be
software-dependent.


## Contributing

Help, bug reports and PR welcome.
