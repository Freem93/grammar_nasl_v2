#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-310-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86049);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:18 $");

  script_cve_id("CVE-2015-0272", "CVE-2015-5156", "CVE-2015-5364", "CVE-2015-5366", "CVE-2015-5697", "CVE-2015-5707", "CVE-2015-6937");
  script_bugtraq_id(75510);
  script_osvdb_id(123996, 125431, 125710, 125846, 127518, 127759);

  script_name(english:"Debian DLA-310-1 : linux-2.6 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the CVEs described below.

CVE-2015-0272

It was discovered that NetworkManager would set IPv6 MTUs based on the
values received in IPv6 RAs (Router Advertisements), without
sufficiently validating these values. A remote attacker could exploit
this attack to disable IPv6 connectivity. This has been mitigated by
adding validation in the kernel.

CVE-2015-5156

Jason Wang discovered that when a virtio_net device is connected to a
bridge in the same VM, a series of TCP packets forwarded through the
bridge may cause a heap buffer overflow. A remote attacker could use
this to cause a denial of service (crash) or possibly for privilege
escalation.

CVE-2015-5364

It was discovered that the Linux kernel does not properly handle
invalid UDP checksums. A remote attacker could exploit this flaw to
cause a denial of service using a flood of UDP packets with invalid
checksums.

CVE-2015-5366

It was discovered that the Linux kernel does not properly handle
invalid UDP checksums. A remote attacker can cause a denial of service
against applications that use epoll by injecting a single packet with
an invalid checksum.

CVE-2015-5697

A flaw was discovered in the md driver in the Linux kernel leading to
an information leak.

CVE-2015-5707

An integer overflow in the SCSI generic driver in the Linux kernel was
discovered. A local user with write permission on a SCSI generic
device could potentially exploit this flaw for privilege escalation.

CVE-2015-6937

It was found that the Reliable Datagram Sockets (RDS) protocol
implementation did not verify that an underlying transport exists when
creating a connection. Depending on how a local RDS application
initialised its sockets, a remote attacker might be able to cause a
denial of service (crash) by sending a crafted packet.

For the oldoldstable distribution (squeeze), these problems have been
fixed in version 2.6.32-48squeeze14.

For the oldstable distribution (wheezy), these problems have been
fixed in version 3.2.68-1+deb7u4 or earlier.

For the stable distribution (jessie), these problems have been fixed
in version 3.16.7-ckt11-1+deb8u4 or earlier.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/09/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/linux-2.6"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"firmware-linux-free", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-base", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-doc-2.6.32", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-486", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686-bigmem", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-amd64", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-i386", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-amd64", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-openvz", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-vserver", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-xen", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-686", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-amd64", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-amd64", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-686", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-486", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem-dbg", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64-dbg", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686-dbg", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64-dbg", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64-dbg", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686-dbg", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64-dbg", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-libc-dev", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-manual-2.6.32", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-patch-debian-2.6.32", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-source-2.6.32", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-support-2.6.32-5", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"linux-tools-2.6.32", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-686", reference:"2.6.32-48squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
