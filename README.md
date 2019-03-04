<!--y
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright 2019 Joyent, Inc.
-->

This repository is part of the Joyent Triton project. See the [contribution
guidelines](https://github.com/joyent/triton/blob/master/CONTRIBUTING.md) --
*Triton does not use GitHub PRs* -- and general documentation at the main
[Triton project](https://github.com/joyent/triton) page.

# Triton Firewall Logger Agent

The firewall-logger-agent (cfwlogd) is a userland daemon that is responsible
for translating firewall events into newline separated json logs.  It does so
by attaching to the kernel device found at `/dev/ipfev` on a SmartOS system
and reading in a buffer of bytes.  Cfwlogd is then responsible for parsing the
buffer into cloud firewall (cfw) logs that will be serialized out to disk. It
is then the job of hermes to upload these logs into the customer's manta
storage.

For more information see [rfd-163](https://github.com/joyent/rfd/tree/master/rfd/0163)

## Development

In order to build firewall-logger-agent you will need a development zone that
has rust 1.33. The component is built by a 2019Q4 image but it is also possible
to use 2018Q4 which is an LTS release and also contains rust 1.33.

## Debug build

This will build a debug build with less optimization but faster build times.

    cargo build

## Release build

This will build a release build that generally takes much longer to compile but
results in much faster code.  This is what is actually deployed. It's worth
noting that `.cargo/config` and `Cargo.toml` include some extra options such as
requiring frame pointers and including debug symbols which are applied in this
mode.

    cargo build --release

## Test

To run the included tests run the following from the top level directory:

    cargo test

One can also run just the individual tests per crate in the workspace by first
changing into the subcrate's directory.

## Documentation

Docs can be generated by running:

    cargo doc

## Linting / Formatting

This project is using the standard rust style guidelines and one should run the
following to have formatting applied automatically:

    cargo fmt

It's also nice to run the rust clippy tool which will catch a bunch of lints
and common mistakes that generally improve the rust code.

    cargo clippy

## License

"Triton Firewall Logger" is licensed under the
[Mozilla Public License version 2.0](http://mozilla.org/MPL/2.0/).
See the file LICENSE.
