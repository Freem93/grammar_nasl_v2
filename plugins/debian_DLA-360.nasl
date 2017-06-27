#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-360-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87265);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2013-7446", "CVE-2015-7799", "CVE-2015-7833", "CVE-2015-7990", "CVE-2015-8324");
  script_osvdb_id(127759, 128557, 128845, 130525, 130622);

  script_name(english:"Debian DLA-360-1 : linux-2.6 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the CVEs described below.

CVE-2013-7446

Dmitry Vyukov discovered that a particular sequence of valid
operations on local (AF_UNIX) sockets can result in a use-after-free.
This may be used to cause a denial of service (crash) or possibly for
privilege escalation.

CVE-2015-7799

&#x90ED;&#x6C38;&#x521A; discovered that a user granted access to
/dev/ppp can cause a denial of service (crash) by passing invalid
parameters to the PPPIOCSMAXCID ioctl. This also applies to ISDN PPP
device nodes.

CVE-2015-7833

Sergej Schumilo, Hendrik Schwartke and Ralf Spenneberg discovered a
flaw in the processing of certain USB device descriptors in the
usbvision driver. An attacker with physical access to the system can
use this flaw to crash the system.

CVE-2015-7990

It was discovered that the fix for CVE-2015-6937 was incomplete. A
race condition when sending a message on unbound socket can still
cause a NULL pointer dereference. A remote attacker might be able to
cause a denial of service (crash) by sending a crafted packet.

CVE-2015-8324

'Valintinr' reported that an attempt to mount a corrupted ext4
filesystem may result in a kernel panic. A user permitted to mount
filesystems could use this flaw to crash the system.

For the oldoldstable distribution (squeeze), these problems have been
fixed in version 2.6.32-48squeeze17. We recommend that you upgrade
your linux-2.6 packages.

For the oldstable (wheezy) and stable (jessie) distributions,
CVE-2015-7833, CVE-2015-7990 and CVE-2015-8324 have been fixed and the
other issues will be fixed soon.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/12/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/linux-2.6"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-linux-free");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-486");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-686-bigmem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-common-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-common-vserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-common-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-openvz-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-openvz-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-vserver-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-vserver-686-bigmem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-vserver-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-xen-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-xen-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-486");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-686-bigmem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-686-bigmem-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-openvz-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-openvz-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-openvz-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-openvz-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-vserver-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-vserver-686-bigmem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-vserver-686-bigmem-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-vserver-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-vserver-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-xen-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-xen-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-xen-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-xen-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-manual-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-patch-debian-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-2.6.32-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-tools-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-linux-system-2.6.32-5-xen-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-linux-system-2.6.32-5-xen-amd64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"firmware-linux-free", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-base", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-doc-2.6.32", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-486", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686-bigmem", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-amd64", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-i386", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-amd64", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-openvz", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-vserver", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-xen", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-686", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-amd64", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-amd64", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-686", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-486", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem-dbg", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64-dbg", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686-dbg", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64-dbg", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64-dbg", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686-dbg", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64-dbg", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-libc-dev", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-manual-2.6.32", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-patch-debian-2.6.32", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-source-2.6.32", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-support-2.6.32-5", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"linux-tools-2.6.32", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-686", reference:"2.6.32-48squeeze17")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze17")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
