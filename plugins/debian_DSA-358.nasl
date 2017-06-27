#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-358. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(15195);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2003-0018", "CVE-2003-0461", "CVE-2003-0462", "CVE-2003-0476", "CVE-2003-0501", "CVE-2003-0550", "CVE-2003-0551", "CVE-2003-0552", "CVE-2003-0619", "CVE-2003-0643");
  script_bugtraq_id(8042, 8233, 10330);
  script_osvdb_id(2353);
  script_xref(name:"DSA", value:"358");

  script_name(english:"Debian DSA-358-4 : linux-kernel-2.4.18 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of vulnerabilities have been discovered in the Linux kernel.

  - CAN-2003-0461: /proc/tty/driver/serial in Linux 2.4.x
    reveals the exact number of characters used in serial
    links, which could allow local users to obtain
    potentially sensitive information such as the length of
    passwords. This bug has been fixed by restricting access
    to /proc/tty/driver/serial.
  - CAN-2003-0462: A race condition in the way env_start and
    env_end pointers are initialized in the execve system
    call and used in fs/proc/base.c on Linux 2.4 allows
    local users to cause a denial of service (crash).

  - CAN-2003-0476: The execve system call in Linux 2.4.x
    records the file descriptor of the executable process in
    the file table of the calling process, which allows
    local users to gain read access to restricted file
    descriptors.

  - CAN-2003-0501: The /proc filesystem in Linux allows
    local users to obtain sensitive information by opening
    various entries in /proc/self before executing a setuid
    program, which causes the program to fail to change the
    ownership and permissions of those entries.

  - CAN-2003-0550: The STP protocol, as enabled in Linux
    2.4.x, does not provide sufficient security by design,
    which allows attackers to modify the bridge topology.
    This bug has been fixed by disabling STP by default.

  - CAN-2003-0551: The STP protocol, as enabled in Linux
    2.4.x, does not provide sufficient security by design,
    which allows attackers to modify the bridge topology.

  - CAN-2003-0552: Linux 2.4.x allows remote attackers to
    spoof the bridge forwarding table via forged packets
    whose source addresses are the same as the target.

  - CAN-2003-0018: Linux kernel 2.4.10 through 2.4.21-pre4
    does not properly handle the O_DIRECT feature, which
    allows local attackers with write privileges to read
    portions of previously deleted files, or cause file
    system corruption. This bug has been fixed by disabling
    O_DIRECT.

  - CAN-2003-0619: Integer signedness error in the decode_fh
    function of nfs3xdr.c in Linux kernel before 2.4.21
    allows remote attackers to cause a denial of service
    (kernel panic) via a negative size value within XDR data
    of an NFSv3 procedure call.

This advisory covers only the i386 and alpha architectures. Other
architectures will be covered by separate advisories."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-358"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) on the i386 architecture, these
problems have been fixed in kernel-source-2.4.18 version 2.4.18-13,
kernel-image-2.4.18-1-i386 version 2.4.18-11, and
kernel-image-2.4.18-i386bf version 2.4.18-5woody4.

For the stable distribution (woody) on the alpha architecture, these
problems have been fixed in kernel-source-2.4.18 version 2.4.18-13 and
kernel-image-2.4.18-1-alpha version 2.4.18-10.

We recommend that you update your kernel packages.

If you are using the kernel installed by the installation system when
the 'bf24' option is selected (for a 2.4.x kernel), you should install
the kernel-image-2.4.18-bf2.4 package. If you installed a different
kernel-image package after installation, you should install the
corresponding 2.4.18-1 kernel. You may use the table below as a guide.

    | If 'uname -r' shows: | Install this package: | 2.4.18-bf2.4 |
    kernel-image-2.4.18-bf2.4 | 2.4.18-386 | kernel-image-2.4.18-1-386
    | 2.4.18-586tsc | kernel-image-2.4.18-1-586tsc | 2.4.18-686 |
    kernel-image-2.4.18-1-686 | 2.4.18-686-smp |
    kernel-image-2.4.18-1-686-smp | 2.4.18-k6 |
    kernel-image-2.4.18-1-k6 | 2.4.18-k7 | kernel-image-2.4.18-1-k7

NOTE: This kernel is binary compatible with the previous kernel
security update, but not binary compatible with the corresponding
kernel included in Debian 3.0r1. If you have not already applied the
previous security update (kernel-image-2.4.18-bf2.4 version
2.4.18-5woody1 or any of the 2.4.18-1-* kernels), then any custom
modules will need to be rebuilt in order to work with the new kernel.
New PCMCIA modules are provided for all of the above kernels.

NOTE: A system reboot will be required immediately after the upgrade
in order to replace the running kernel. Remember to read carefully and
follow the instructions given during the kernel upgrade process."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kernel-alpha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kernel-i386");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/29");
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
if (deb_check(release:"3.0", prefix:"kernel-doc-2.4.18", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-386", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-586tsc", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-686", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-686-smp", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-generic", reference:"2.4.18-10")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-k6", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-k7", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-smp", reference:"2.4.18-10")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-bf2.4", reference:"2.4.18-5woody4")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-386", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-586tsc", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-686", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-686-smp", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-generic", reference:"2.4.18-10")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-k6", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-k7", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-smp", reference:"2.4.18-10")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-bf2.4", reference:"2.4.18-5woody4")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-386", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-586tsc", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-686", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-686-smp", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-k6", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-k7", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-source-2.4.18", reference:"2.4.18-13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
