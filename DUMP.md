# JSON Dumping for HickoryDNS

### Modified Section

Implement `Dump` and `Walk` trait for recursive data structure dumping. Dump the necessary fields at the entry function.

### Dumping

Pre-requisite:

* Make sure the code is in branch `dev-dump` of `hickory-dns/`
* Compile with `rust 1.69.0`

```bash
# install correct version of rust
rustup default 1.69-x86_64-unknown-linux-gnu
# in hickory-dns/
cargo build --release -p hickory-dns
```

In `zone/`, we provide a script `zone.sh` to batch process zone files.

Usage: `bash zone.sh <test_suite>`

It will get all zone files in `<test_suite>_zone/`, and generate `ctx.json` in `<test_suite>/`. It will also generate `ctx.json` in `<test_suite>_filter/` for zones without `CNAME` and `DNAME`.

```bash
# in hickory-dns/
cd zone
# Process buggy_zone/ and generate ctx.json in buggy/ and buggy_filter/
bash zone.sh buggy

# copy buggy/ to iceberg/test/hickory-dns/json/ for verification
```