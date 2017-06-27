#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-336. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(15173);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2002-0429", "CVE-2002-1380", "CVE-2003-0001", "CVE-2003-0127", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247", "CVE-2003-0248", "CVE-2003-0364");
  script_bugtraq_id(4259, 6420, 6535, 7112, 7600, 7601, 7791, 7793, 7797);
  script_osvdb_id(4456);
  script_xref(name:"DSA", value:"336");

  script_name(english:"Debian DSA-336-1 : linux-kernel-2.2.20 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of vulnerabilities have been discovered in the Linux kernel.

  - CAN-2002-1380: Linux kernel 2.2.x allows local users to
    cause a denial of service (crash) by using the mmap()
    function with a PROT_READ parameter to access
    non-readable memory pages through the /proc/pid/mem
    interface.
  - CVE-2002-0429: The iBCS routines in
    arch/i386/kernel/traps.c for Linux kernels 2.4.18 and
    earlier on x86 systems allow local users to kill
    arbitrary processes via a binary compatibility interface
    (lcall)

  - CAN-2003-0001: Multiple ethernet Network Interface Card
    (NIC) device drivers do not pad frames with null bytes,
    which allows remote attackers to obtain information from
    previous packets or kernel memory by using malformed
    packets

  - CAN-2003-0127: The kernel module loader allows local
    users to gain root privileges by using ptrace to attach
    to a child process that is spawned by the kernel

  - CAN-2003-0244: The route cache implementation in Linux
    2.4, and the Netfilter IP conntrack module, allows
    remote attackers to cause a denial of service (CPU
    consumption) via packets with forged source addresses
    that cause a large number of hash table collisions
    related to the PREROUTING chain

  - CAN-2003-0246: The ioperm system call in Linux kernel
    2.4.20 and earlier does not properly restrict
    privileges, which allows local users to gain read or
    write access to certain I/O ports.

  - CAN-2003-0247: vulnerability in the TTY layer of the
    Linux kernel 2.4 allows attackers to cause a denial of
    service ('kernel oops')

  - CAN-2003-0248: The mxcsr code in Linux kernel 2.4 allows
    attackers to modify CPU state registers via a malformed
    address.

  - CAN-2003-0364: The TCP/IP fragment reassembly handling
    in the Linux kernel 2.4 allows remote attackers to cause
    a denial of service (CPU consumption) via certain
    packets that cause a large number of hash table
    collisions

This advisory provides updated 2.2.20 kernel source, and binary kernel
images for the i386 architecture. Other architectures and kernel
versions will be covered by separate advisories."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-336"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) on the i386 architecture, these
problems have been fixed in kernel-source-2.2.20 version
2.2.20-5woody2 and kernel-image-i386 version 2.2.20-5woody3.

We recommend that you update your kernel packages.

NOTE: A system reboot will be required immediately after the upgrade
in order to replace the running kernel. Remember to read carefully and
follow the instructions given during the kernel upgrade process.

NOTE: These kernels are not binary-compatible with the previous
version. Any loadable modules will need to be recompiled in order to
work with the new kernel."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.2.20-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.2.20");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/06/29");
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
if (deb_check(release:"3.0", prefix:"kernel-doc-2.2.20", reference:"2.2.20-5woody2")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.2.20", reference:"2.2.20-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.2.20-compact", reference:"2.2.20-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.2.20-idepci", reference:"2.2.20-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.2.20", reference:"2.2.20-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.2.20-compact", reference:"2.2.20-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.2.20-idepci", reference:"2.2.20-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-source-2.2.20", reference:"2.2.20-5woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
