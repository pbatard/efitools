[![Build Status](https://img.shields.io/github/actions/workflow/status/pbatard/efitools/Linux.yml?style=flat-square&label=Linux/gnu-efi%20Build)](https://github.com/pbatard/efitools/actions/efitools/Linux.yml)
[![Release](https://img.shields.io/github/release/pbatard/efitools.svg?style=flat-square&label=Release)](https://github.com/pbatard/efitools/releases)
[![Licence](https://img.shields.io/badge/license-GPLv2-blue.svg?style=flat-square&label=License)](https://www.gnu.org/licenses/gpl-2.0)
[![Downloads](https://img.shields.io/github/downloads/pbatard/efitools/total.svg?label=Downloads&style=flat-square)](https://github.com/pbatard/efitools/releases)

efitools - useful tools for manipulating UEFI secure boot platforms
===============================

## Description

This repository aims at providing up to date versions of the EFI binaries from the efitools
project originally available at https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git/
and with the latest Debian patches applied on top of it. 

Our goal with this is to provide users with the ability to manipulate their Secure Boot
databases in a convenient manner, from the UEFI Shell, regardless of the OS they are using
(or even on platforms where no OS is installed).

Currently, we provide builds of the efitools EFI utilities for:
- x86 64-bit (`x64`)
- x86 32-bit (`ia32`)
- ARM 32-bit (`arm)
- ARM 64-bit (`aa64`)
- RISC-V 64-bit (`riscv64`)
- LoongArch 64-bit (`loongarch64`)

From these archives, the utility you are most likely to be interested with is probably
`KeyTool.efi`, that allows you to add/remove/save and perform other manipulations to the
Secure Boot `PK`, `KEK`, `db`, `dbx`, `dbt`, `MokList` and `MokListX` stores.

The original README for the project can also be found at:
https://github.com/pbatard/efitools/blob/master/README


## Usage

Create a bootable media with the UEFI Shell, such as the one you can download from
https://github.com/pbatard/UEFI-Shell and extract the archive that is relevant to your
platform on that media.

Then boot that media and invoke the utility of your choice from the Shell command line.


## Compilation

Whereas the non EFI utilities should also work, the goal of this project is to provide
the EFi binaries so, once you have cloned the repository you should just be able to invoke
`make efi`.

If cross compiling, you may also invoke one of:
- `make efi ARCH=ia32`
- `make efi ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-`
- `make efi ARCH=aarch64 CROSS_COMPILE=aarch64-linux-gnu-`
- `make efi ARCH=riscv64 CROSS_COMPILE=riscv64-linux-gnu-`
- `make efi ARCH=loongarch64 CROSS_COMPILE=loongarch64-unknown-linux-gnu-`
