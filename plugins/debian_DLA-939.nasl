#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-939-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100133);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/12 13:30:58 $");

  script_cve_id("CVE-2016-9603", "CVE-2017-7718", "CVE-2017-7980");
  script_osvdb_id(153753, 155921, 156069);

  script_name(english:"Debian DLA-939-1 : qemu-kvm security update");
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

CVE-2016-9603

qemu-kvm built with the Cirrus CLGD 54xx VGA Emulator and the VNC
display driver support is vulnerable to a heap buffer overflow issue.
It could occur when Vnc client attempts to update its display after a
vga operation is performed by a guest.

A privileged user/process inside guest could use this flaw
to crash the Qemu process resulting in DoS OR potentially
leverage it to execute arbitrary code on the host with
privileges of the Qemu process.

CVE-2017-7718

qemu-kvm built with the Cirrus CLGD 54xx VGA Emulator support is
vulnerable to an out-of-bounds access issue. It could occur while
copying VGA data via bitblt functions cirrus_bitblt_rop_fwd_transp_
and/or cirrus_bitblt_rop_fwd_.

A privileged user inside guest could use this flaw to crash
the Qemu process resulting in DoS.

CVE-2017-7980

qemu-kvm built with the Cirrus CLGD 54xx VGA Emulator support is
vulnerable to an out-of-bounds r/w access issues. It could occur while
copying VGA data via various bitblt functions.

A privileged user inside guest could use this flaw to crash
the Qemu process resulting in DoS OR potentially execute
arbitrary code on a host with privileges of Qemu process on
the host.

For Debian 7 'Wheezy', these problems have been fixed in version
1.1.2+dfsg-6+deb7u21.

We recommend that you upgrade your qemu-kvm packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/qemu-kvm"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected kvm, qemu-kvm, and qemu-kvm-dbg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"kvm", reference:"1.1.2+dfsg-6+deb7u21")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-kvm", reference:"1.1.2+dfsg-6+deb7u21")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-kvm-dbg", reference:"1.1.2+dfsg-6+deb7u21")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
