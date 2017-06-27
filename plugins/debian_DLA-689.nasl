#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-689-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(94411);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2016-7909", "CVE-2016-8909", "CVE-2016-8910");
  script_osvdb_id(145163, 146244, 146245);

  script_name(english:"Debian DLA-689-1 : qemu-kvm security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in qemu-kvm, a full
virtualization solution on x86 hardware based on Quick Emulator(Qemu).
The Common Vulnerabilities and Exposures project identifies the
following problems :

CVE-2016-7909

Quick Emulator(Qemu) built with the AMD PC-Net II emulator support is
vulnerable to an infinite loop issue. It could occur while receiving
packets via pcnet_receive().

A privileged user/process inside guest could use this issue
to crash the Qemu process on the host leading to DoS.

CVE-2016-8909

Quick Emulator(Qemu) built with the Intel HDA controller emulation
support is vulnerable to an infinite loop issue. It could occur while
processing the DMA buffer stream while doing data transfer in
'intel_hda_xfer'.

A privileged user inside guest could use this flaw to
consume excessive CPU cycles on the host, resulting in DoS.

CVE-2016-8910

Quick Emulator(Qemu) built with the RTL8139 ethernet controller
emulation support is vulnerable to an infinite loop issue. It could
occur while transmitting packets in C+ mode of operation.

A privileged user inside guest could use this flaw to
consume excessive CPU cycles on the host, resulting in DoS
situation.

Further issues fixed where the CVE requests are pending :

  - Quick Emulator(Qemu) built with the i8255x (PRO100) NIC
    emulation support is vulnerable to a memory leakage
    issue. It could occur while unplugging the device, and
    doing so repeatedly would result in leaking host memory
    affecting, other services on the host.

    A privileged user inside guest could use this flaw to
    cause a DoS on the host and/or potentially crash the
    Qemu process on the host.

  - Quick Emulator(Qemu) built with the VirtFS, host
    directory sharing via Plan 9 File System(9pfs) support,
    is vulnerable to a several memory leakage issues.

    A privileged user inside guest could use this flaw to
    leak the host memory bytes resulting in DoS for other
    services.

  - Quick Emulator(Qemu) built with the VirtFS, host
    directory sharing via Plan 9 File System(9pfs) support,
    is vulnerable to an integer overflow issue. It could
    occur by accessing xattributes values.

    A privileged user inside guest could use this flaw to
    crash the Qemu process instance resulting in DoS.

  - Quick Emulator(Qemu) built with the VirtFS, host
    directory sharing via Plan 9 File System(9pfs) support,
    is vulnerable to memory leakage issue. It could occur
    while creating extended attribute via 'Txattrcreate'
    message.

    A privileged user inside guest could use this flaw to
    leak host memory, thus affecting other services on the
    host and/or potentially crash the Qemu process on the
    host.

For Debian 7 'Wheezy', these problems have been fixed in version
1.1.2+dfsg-6+deb7u18.

We recommend that you upgrade your qemu-kvm packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/10/msg00046.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/qemu-kvm"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected kvm, qemu-kvm, and qemu-kvm-dbg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"kvm", reference:"1.1.2+dfsg-6+deb7u18")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-kvm", reference:"1.1.2+dfsg-6+deb7u18")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-kvm-dbg", reference:"1.1.2+dfsg-6+deb7u18")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
