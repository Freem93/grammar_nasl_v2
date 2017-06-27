#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-311. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(15148);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2002-0429", "CVE-2003-0001", "CVE-2003-0127", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247", "CVE-2003-0248", "CVE-2003-0364");
  script_osvdb_id(3873, 4456);
  script_xref(name:"DSA", value:"311");

  script_name(english:"Debian DSA-311-1 : linux-kernel-2.4.18 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of vulnerabilities have been discovered in the Linux kernel.

CVE-2002-0429: The iBCS routines in arch/i386/kernel/traps.c for Linux
kernels 2.4.18 and earlier on x86 systems allow local users to kill
arbitrary processes via a binary compatibility interface (lcall).

CAN-2003-0001: Multiple ethernet Network Interface Card (NIC) device
drivers do not pad frames with null bytes, which allows remote
attackers to obtain information from previous packets or kernel memory
by using malformed packets.

CAN-2003-0127: The kernel module loader allows local users to gain
root privileges by using ptrace to attach to a child process that is
spawned by the kernel.

CAN-2003-0244: The route cache implementation in Linux 2.4, and the
Netfilter IP conntrack module, allows remote attackers to cause a
denial of service (CPU consumption) via packets with forged source
addresses that cause a large number of hash table collisions related
to the PREROUTING chain.

CAN-2003-0246: The ioperm system call in Linux kernel 2.4.20 and
earlier does not properly restrict privileges, which allows local
users to gain read or write access to certain I/O ports.

CAN-2003-0247: Vulnerability in the TTY layer of the Linux kernel 2.4
allows attackers to cause a denial of service ('kernel oops').

CAN-2003-0248: The mxcsr code in Linux kernel 2.4 allows attackers to
modify CPU state registers via a malformed address.

CAN-2003-0364: The TCP/IP fragment reassembly handling in the Linux
kernel 2.4 allows remote attackers to cause a denial of service (CPU
consumption) via certain packets that cause a large number of hash
table collisions.

This advisory covers only the i386 (Intel IA32) architectures. Other
architectures will be covered by separate advisories."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-311"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) on the i386 architecture, these
problems have been fixed in kernel-source-2.4.18 version 2.4.18-9,
kernel-image-2.4.18-1-i386 version 2.4.18-8, and
kernel-image-2.4.18-i386bf version 2.4.18-5woody1.

We recommend that you update your kernel packages.

If you are using the kernel installed by the installation system when
the 'bf24' option is selected (for a 2.4.x kernel), you should install
the kernel-image-2.4.18-bf2.4 package. If you installed a different
kernel-image package after installation, you should install the
corresponding 2.4.18-1 kernel. You may use the table below as a guide.

| If 'uname -r' shows: | Install this package: | 2.4.18-bf2.4 |
kernel-image-2.4.18-bf2.4 | 2.4.18-386 | kernel-image-2.4.18-1-386 |
2.4.18-586tsc | kernel-image-2.4.18-1-586tsc | 2.4.18-686 |
kernel-image-2.4.18-1-686 | 2.4.18-686-smp |
kernel-image-2.4.18-1-686-smp | 2.4.18-k6 | kernel-image-2.4.18-1-k6 |
2.4.18-k7 | kernel-image-2.4.18-1-k7

NOTE: that this kernel is not binary compatible with the previous
version. For this reason, the kernel has a different version number
and will not be installed automatically as part of the normal upgrade
process. Any custom modules will need to be rebuilt in order to work
with the new kernel. New PCMCIA modules are provided for all of the
above kernels.

NOTE: A system reboot will be required immediately after the upgrade
in order to replace the running kernel. Remember to read carefully and
follow the instructions given during the kernel upgrade process."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"kernel-doc-2.4.18", reference:"2.4.18-9")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-386", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-586tsc", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-686", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-686-smp", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-k6", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-k7", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-bf2.4", reference:"2.4.18-5woody1")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-386", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-586tsc", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-686", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-686-smp", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-k6", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-k7", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-bf2.4", reference:"2.4.18-5woody1")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-386", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-586tsc", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-686", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-686-smp", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-k6", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-k7", reference:"2.4.18-8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-source-2.4.18", reference:"2.4.18-9")) flag++;
if (deb_check(release:"3.0", prefix:"pcmcia-modules-2.4.18-bf2.4", reference:"3.1.33-6woody1k5woody1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
