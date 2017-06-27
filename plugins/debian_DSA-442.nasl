#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-442. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(15279);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2002-0429", "CVE-2003-0001", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247", "CVE-2003-0248", "CVE-2003-0364", "CVE-2003-0961", "CVE-2003-0985", "CVE-2004-0077");
  script_bugtraq_id(4259, 6535, 7600, 7601, 7791, 7793, 7797, 9138, 9356, 9686);
  script_osvdb_id(3986, 4456);
  script_xref(name:"CERT", value:"981222");
  script_xref(name:"DSA", value:"442");

  script_name(english:"Debian DSA-442-1 : linux-kernel-2.4.17-s390 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security related problems have been fixed in the Linux kernel
2.4.17 used for the S/390 architecture, mostly by backporting fixes
from 2.4.18 and incorporating recent security fixes. The corrections
are listed below with the identification from the Common
Vulnerabilities and Exposures (CVE) project :

  - CVE-2002-0429 :
    The iBCS routines in arch/i386/kernel/traps.c for Linux
    kernels 2.4.18 and earlier on x86 systems allow local
    users to kill arbitrary processes via a binary
    compatibility interface (lcall).

  - CAN-2003-0001 :

    Multiple ethernet network interface card (NIC) device
    drivers do not pad frames with null bytes, which allows
    remote attackers to obtain information from previous
    packets or kernel memory by using malformed packets, as
    demonstrated by Etherleak.

  - CAN-2003-0244 :

    The route cache implementation in Linux 2.4, and the
    Netfilter IP conntrack module, allows remote attackers
    to cause a denial of service (CPU consumption) via
    packets with forged source addresses that cause a large
    number of hash table collisions related to the
    PREROUTING chain.

  - CAN-2003-0246 :

    The ioperm system call in Linux kernel 2.4.20 and
    earlier does not properly restrict privileges, which
    allows local users to gain read or write access to
    certain I/O ports.

  - CAN-2003-0247 :

    A vulnerability in the TTY layer of the Linux kernel 2.4
    allows attackers to cause a denial of service ('kernel
    oops').

  - CAN-2003-0248 :

    The mxcsr code in Linux kernel 2.4 allows attackers to
    modify CPU state registers via a malformed address.

  - CAN-2003-0364 :

    The TCP/IP fragment reassembly handling in the Linux
    kernel 2.4 allows remote attackers to cause a denial of
    service (CPU consumption) via certain packets that cause
    a large number of hash table collisions.

  - CAN-2003-0961 :

    An integer overflow in brk() system call (do_brk()
    function) for Linux allows a local attacker to gain root
    privileges. Fixed upstream in Linux 2.4.23.

  - CAN-2003-0985 :

    Paul Starzetz discovered a flaw in bounds checking in
    mremap() in the Linux kernel (present in version 2.4.x
    and 2.6.x) which may allow a local attacker to gain root
    privileges. Version 2.2 is not affected by this bug.
    Fixed upstream in Linux 2.4.24.

  - CAN-2004-0077 :

    Paul Starzetz and Wojciech Purczynski of isec.pl
    discovered a critical security vulnerability in the
    memory management code of Linux inside the mremap(2)
    system call. Due to missing function return value check
    of internal functions a local attacker can gain root
    privileges. Fixed upstream in Linux 2.4.25 and 2.6.3."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://isec.pl/vulnerabilities/isec-0013-mremap.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://isec.pl/vulnerabilities/isec-0014-mremap-unmap.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-442"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Linux kernel packages immediately.

For the stable distribution (woody) these problems have been fixed in
version 2.4.17-2.woody.3 of s390 images and in version
0.0.20020816-0.woody.2 of the patch packages.

 Vulnerability matrix for CAN-2004-0077"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.4.17-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-patch-2.4.17-s390");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/19");
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
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.17", reference:"2.4.17-2.woody.3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-s390", reference:"2.4.17-2.woody.3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-patch-2.4.17-s390", reference:"0.0.20020816-0.woody.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
