#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-423. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(15260);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2003-0001", "CVE-2003-0018", "CVE-2003-0127", "CVE-2003-0461", "CVE-2003-0462", "CVE-2003-0476", "CVE-2003-0501", "CVE-2003-0550", "CVE-2003-0551", "CVE-2003-0552", "CVE-2003-0961", "CVE-2003-0985");
  script_bugtraq_id(6535, 6763, 7112, 8002, 8042, 8233, 9138, 9356, 10330);
  script_xref(name:"DSA", value:"423");

  script_name(english:"Debian DSA-423-1 : linux-kernel-2.4.17-ia64 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The IA-64 maintainers fixed several security related bugs in the Linux
kernel 2.4.17 used for the IA-64 architecture, mostly by backporting
fixes from 2.4.18. The corrections are listed below with the
identification from the Common Vulnerabilities and Exposures (CVE)
project :

  - CAN-2003-0001 :
    Multiple ethernet network interface card (NIC) device
    drivers do not pad frames with null bytes, which allows
    remote attackers to obtain information from previous
    packets or kernel memory by using malformed packets, as
    demonstrated by Etherleak.

  - CAN-2003-0018 :

    Linux kernel 2.4.10 through 2.4.21-pre4 does not
    properly handle the O_DIRECT feature, which allows local
    attackers with write privileges to read portions of
    previously deleted files, or cause file system
    corruption.

  - CAN-2003-0127 :

    The kernel module loader in Linux kernel 2.2.x before
    2.2.25, and 2.4.x before 2.4.21, allows local users to
    gain root privileges by using ptrace to attach to a
    child process which is spawned by the kernel.

  - CAN-2003-0461 :

    The virtual file /proc/tty/driver/serial in Linux 2.4.x
    reveals the exact number of characters used in serial
    links, which could allow local users to obtain
    potentially sensitive information such as the length of
    passwords.

  - CAN-2003-0462 :

    A race condition in the way env_start and env_end
    pointers are initialized in the execve system call and
    used in fs/proc/base.c on Linux 2.4 allows local users
    to cause a denial of service (crash).

  - CAN-2003-0476 :

    The execve system call in Linux 2.4.x records the file
    descriptor of the executable process in the file table
    of the calling process, which allows local users to gain
    read access to restricted file descriptors.

  - CAN-2003-0501 :

    The /proc filesystem in Linux allows local users to
    obtain sensitive information by opening various entries
    in /proc/self before executing a setuid program, which
    causes the program to fail to change the ownership and
    permissions of those entries.

  - CAN-2003-0550 :

    The STP protocol, as enabled in Linux 2.4.x, does not
    provide sufficient security by design, which allows
    attackers to modify the bridge topology.

  - CAN-2003-0551 :

    The STP protocol implementation in Linux 2.4.x does not
    properly verify certain lengths, which could allow
    attackers to cause a denial of service.

  - CAN-2003-0552 :

    Linux 2.4.x allows remote attackers to spoof the bridge
    Forwarding table via forged packets whose source
    addresses are the same as the target.

  - CAN-2003-0961 :

    An integer overflow in brk system call (do_brk function)
    for Linux kernel 2.4.22 and earlier allows local users
    to gain root privileges.

  - CAN-2003-0985 :

    The mremap system call (do_mremap) in Linux kernel 2.4
    and 2.6 does not properly perform boundary checks, which
    allows local users to cause a denial of service and
    possibly gain privileges by causing a remapping of a
    virtual memory area (VMA) to create a zero length VMA."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-423"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) this problem has been fixed in
version kernel-image-2.4.17-ia64 for the ia64 architecture. Other
architectures are already or will be fixed separately."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.4.17-ia64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.17-ia64", reference:"011226.15")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-itanium", reference:"011226.15")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-itanium-smp", reference:"011226.15")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-mckinley", reference:"011226.15")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-mckinley-smp", reference:"011226.15")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-source-2.4.17-ia64", reference:"011226.15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
