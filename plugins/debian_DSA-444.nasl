#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-444. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15281);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/04/25 14:45:37 $");

  script_cve_id("CVE-2004-0077");
  script_bugtraq_id(9686);
  script_osvdb_id(3986);
  script_xref(name:"CERT", value:"981222");
  script_xref(name:"DSA", value:"444");

  script_name(english:"Debian DSA-444-1 : linux-kernel-2.4.17-ia64 - missing function return value check");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Paul Starzetz and Wojciech Purczynski of isec.pl discovered a critical
security vulnerability in the memory management code of Linux inside
the mremap(2) system call. Due to missing function return value check
of internal functions a local attacker can gain root privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://isec.pl/vulnerabilities/isec-0014-mremap-unmap.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-444"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Linux kernel packages immediately.

For the stable distribution (woody) this problem has been fixed in
version 011226.16 of ia64 kernel source and images.

Other architectures are or will be mentioned in a separate advisory
respectively or are not affected (m68k).

This problem is also fixed in the upstream version of Linux 2.4.25 and
2.6.3.

 Vulnerability matrix for CAN-2004-0077"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.4.17-ia64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/18");
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
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.17-ia64", reference:"011226.16")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-itanium", reference:"011226.16")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-itanium-smp", reference:"011226.16")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-mckinley", reference:"011226.16")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-mckinley-smp", reference:"011226.16")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-source-2.4.17-ia64", reference:"011226.16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
