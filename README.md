*******************************************************************************

### What organization or people are asking to have this signed?

*******************************************************************************

Heimdal Security A/S, we have a feature that uses the iPXE firmware in order to help customers deploy their own OS images and to make it work with Secure Boot we need an approve from you.

*******************************************************************************

### What product or service is this for?

*******************************************************************************

This shim will be used to load [iPXE](https://github.com/ipxe/ipxe) with [wimboot](https://github.com/ipxe/wimboot).

*******************************************************************************

### What's the justification that this really does need to be signed for the whole world to be able to boot it?

*******************************************************************************

It is a module used strictly by Heimdal Security customers. The feature we are building aims to help our customers deploy their own OS images.

*******************************************************************************

### Why are you unable to reuse shim from another distro that is already signed?

*******************************************************************************

Currently there are no distros that provide a Secure Boot version of iPXE.

*******************************************************************************

### Who is the primary contact for security updates, etc.?

The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.

*******************************************************************************

- Name: Gabriel Necoara
- Position: Developer
- Email address: gne@heimdalsecurity.com
- PGP key fingerprint: A132610080A2C6230294EF57DB40457603E070EF

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************

### Who is the secondary contact for security updates, etc.?

*******************************************************************************

- Name: Cosmin Toader
- Position: CTO
- Email address: cgt@heimdalsecurity.com
- PGP key fingerprint: 75EF91CAFEA62EFC027A1A3AC080DC6AA84FCF73

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************

### Were these binaries created from the 15.8 shim release tar?

Please create your shim binaries starting with the 15.8 shim release tar file: https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.8 and contains the appropriate gnu-efi source.

*******************************************************************************

Yes, these binaries were created from the `15.8` tag.

*******************************************************************************

### URL for a repo that contains the exact code which was built to result in your binary:

*******************************************************************************

https://github.com/gne227/shim/tree/ipxe-15.8

*******************************************************************************

### What patches are being applied and why:

Mention all the external patches and build process modifications, which are used during your building process, that make your shim binary be the exact one that you posted as part of this application.

*******************************************************************************

Most of the changes where cherry-picked from the [Michael Brown submission for ipxe](https://github.com/ipxe/shim/commits).

* [Add ipxe.der certificate](https://github.com/gne227/shim/commit/f904209dd77d55041a8c662fe0accca889ab4c06)
* [Add GitHub workflow to build x64 and aa64 binaries](https://github.com/gne227/shim/commit/335f134953449b372717b2c5af69b5e43659ee20)
* [Use iPXE code-signing certificate as vendor certificate](https://github.com/gne227/shim/commit/f24be3cd1dcdb3ef0cff918130961618cecfb286)
* [Set "ipxe.efi" as default loader binary name](https://github.com/gne227/shim/commit/8aa9071c1316b0150f9f4f57445ac18e6be7a1f5)
* [Add vendor SBAT data](https://github.com/gne227/shim/commit/8aa9071c1316b0150f9f4f57445ac18e6be7a1f5)
* [Allow next loader path to be derived from shim path](https://github.com/gne227/shim/commit/f8d6e44914204b97d8282e710881b1d6a6e0b445)
* [Add documentation](https://github.com/gne227/shim/commit/aa7ed12ca4614342ba1e2d073293730a59d6bb38)
* [Modify SBAT URL](https://github.com/gne227/shim/commit/489027a2253fd08ff515c0671335386c14a44dbd)


*******************************************************************************

### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.

*******************************************************************************

No, the NX bit is not set.

*******************************************************************************

### What exact implementation of Secure Boot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)

*******************************************************************************

Not applicable: this shim will not be used to load GRUB2.

*******************************************************************************

### Do you have fixes for all the following GRUB2 CVEs applied?

**Skip this, if you're not using GRUB2, otherwise make sure these are present and confirm with _yes_.**

* 2020 July - BootHole
  * Details: https://lists.gnu.org/archive/html/grub-devel/2020-07/msg00034.html
  * CVE-2020-10713
  * CVE-2020-14308
  * CVE-2020-14309
  * CVE-2020-14310
  * CVE-2020-14311
  * CVE-2020-15705
  * CVE-2020-15706
  * CVE-2020-15707
* March 2021
  * Details: https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html
  * CVE-2020-14372
  * CVE-2020-25632
  * CVE-2020-25647
  * CVE-2020-27749
  * CVE-2020-27779
  * CVE-2021-3418 (if you are shipping the shim_lock module)
  * CVE-2021-20225
  * CVE-2021-20233
* June 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-06/msg00035.html, SBAT increase to 2
  * CVE-2021-3695
  * CVE-2021-3696
  * CVE-2021-3697
  * CVE-2022-28733
  * CVE-2022-28734
  * CVE-2022-28735
  * CVE-2022-28736
  * CVE-2022-28737
* November 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-11/msg00059.html, SBAT increase to 3
  * CVE-2022-2601
  * CVE-2022-3775
* October 2023 - NTFS vulnerabilities
  * Details: https://lists.gnu.org/archive/html/grub-devel/2023-10/msg00028.html, SBAT increase to 4
  * CVE-2023-4693
  * CVE-2023-4692

*******************************************************************************

Not applicable: this shim will not be used to load GRUB2.

*******************************************************************************

### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 4?

*******************************************************************************

Not applicable: this shim will not be used to load GRUB2.

*******************************************************************************

### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?

### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?

*******************************************************************************

Not applicable: this shim will not be used to load GRUB2.

*******************************************************************************

### If your boot chain of trust includes a Linux kernel:

### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?

### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?

### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?

*******************************************************************************

Not applicable: this shim will not be used to load a Linux kernel.

*******************************************************************************

### Do you build your signed kernel with additional local patches? What do they do?

*******************************************************************************

Not applicable: this shim will not be used to load a Linux kernel.

*******************************************************************************

### Do you use an ephemeral key for signing kernel modules?

### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.

*******************************************************************************

Not applicable: this shim will not be used to load a Linux kernel.

*******************************************************************************

### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.

### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.

*******************************************************************************

Not applicable: only a single certificate is used and there are no allow-listed hashes.

*******************************************************************************

### If you are re-using the CA certificate from your last shim binary, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs mentioned earlier to vendor_dbx in shim. Please describe your strategy.

This ensures that your new shim+GRUB2 can no longer chainload those older GRUB2 binaries with issues.

If this is your first application or you're using a new CA certificate, please say so here.

*******************************************************************************

Not applicable: this shim will not be used to load GRUB2.

*******************************************************************************

### Is the Dockerfile in your repository the recipe for reproducing the building of your shim binary?

A reviewer should always be able to run `docker build .` to get the exact binary you attached in your application.

*******************************************************************************

The [`Dockerfile`](Dockerfile) provides a reproducible build.

*******************************************************************************

### Which files in this repo are the logs for your build?

This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.

*******************************************************************************

The [`build.log`](build.log) file contains the build log.

*******************************************************************************

### What changes were made in the distro's secure boot chain since your SHIM was last signed?

For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..

Skip this, if this is your first application for having shim signed.

*******************************************************************************

Not applicable: this is a new submission.

*******************************************************************************

### What is the SHA256 hash of your final shim binary?

*******************************************************************************

[`shimx64.efi`](shimx64.efi) caaff3a76e5a79b24b50185093b2342c07da06378ed768b993264c58404f77a9

[`shimaa64.efi`](shimaa64.efi) 9afbdd9a702a1de8020424ca2d13ce150ebd02ae999c2c1c11745b156876ab8f

*******************************************************************************

### How do you manage and protect the keys used in your shim?

Describe the security strategy that is used for key protection. This can range from using hardware tokens like HSMs or Smartcards, air-gapped vaults, physical safes to other good practices.

*******************************************************************************

Key is held in a hardware security module provided by DigiCert.

*******************************************************************************

### Do you use EV certificates as embedded certificates in the shim?

*******************************************************************************

Yes, the certificate [`ipxe.der`](ipxe.der) is an EV certificate issued by DigiCert.

*******************************************************************************

### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, shim + all child shim binaries )?

### Please provide the exact SBAT entries for all binaries you are booting directly through shim.

**Remember to post the entries of all the binaries. Apart from your bootloader, you may also be shipping e.g. a firmware updater, which will also have these.**

*******************************************************************************

Yes.

This shim binary includes the vendor SBAT data:
```
shim.ipxe,1,iPXE,shim,1,https://github.com/gne277/shim
```

This shim will be used to load iPXE, which includes SBAT metadata as
of commit [f4f9adf61](https://github.com/ipxe/ipxe/commit/f4f9adf61).
The current SBAT content in iPXE at the time of writing is:

```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
ipxe,1,iPXE,ipxe.efi,1.21.1+ (g182ee),https://ipxe.org
```

*******************************************************************************

### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?

*******************************************************************************

Not applicable: this shim will not be used to load GRUB2.

*******************************************************************************

### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?

*******************************************************************************

Not applicable: this shim will not be used to load systemd-boot.

*******************************************************************************

### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?

*******************************************************************************

https://github.com/ipxe/ipxe

*******************************************************************************

### If your shim launches any other components apart from your bootloader, please provide further details on what is launched.

*******************************************************************************

This shim will be used only to launch iPXE.

*******************************************************************************

### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.

*******************************************************************************

Not applicable: this shim will not be used to load GRUB2.

*******************************************************************************

### How do the launched components prevent execution of unauthenticated code?

Summarize in one or two sentences, how your secure bootchain works on higher level.

*******************************************************************************

By design, iPXE does not implement any direct binary loaders when
running as a UEFI binary.  All binary image loading is delegated to
the platform's `LoadImage()` and `StartImage()` calls.  There is
therefore no way for iPXE to execute a binary that is not itself
already signed for Secure Boot.

*******************************************************************************

### Does your shim load any loaders that support loading unsigned kernels (e.g. certain GRUB2 configurations)?

*******************************************************************************

No.

*******************************************************************************

### What kernel are you using? Which patches and configuration does it include to enforce Secure Boot?

*******************************************************************************

Not applicable: this shim will not be used to load a Linux kernel.

*******************************************************************************

### Add any additional information you think we may need to validate this shim signing application.

*******************************************************************************