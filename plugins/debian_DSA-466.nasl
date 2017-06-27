#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-466. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15303);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/04/25 14:45:37 $");

  script_cve_id("CVE-2004-0077");
  script_bugtraq_id(9686);
  script_osvdb_id(3986);
  script_xref(name:"CERT", value:"981222");
  script_xref(name:"DSA", value:"466");

  script_name(english:"Debian DSA-466-1 : linux-kernel-2.2.10-powerpc-apus - failing function and TLB flush");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Paul Starzetz and Wojciech Purczynski of isec.pl discovered a critical
security vulnerability in the memory management code of Linux inside
the mremap(2) system call. Due to flushing the TLB (Translation
Lookaside Buffer, an address cache) too early it is possible for an
attacker to trigger a local root exploit.

The attack vectors for 2.4.x and 2.2.x kernels are exclusive for the
respective kernel series, though. We formerly believed that the
exploitable vulnerability in 2.4.x does not exist in 2.2.x which is
still true. However, it turned out that a second (sort of)
vulnerability is indeed exploitable in 2.2.x, but not in 2.4.x, with a
different exploit, of course."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://isec.pl/vulnerabilities/isec-0014-mremap-unmap.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-466"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Linux kernel package.

For the stable distribution (woody) this problem has been fixed in
version 2.2.10-13woody1 of 2.2 kernel images for the powerpc/apus
architecture and in version 2.2.10-2 of Linux 2.2.10 source.

You are strongly advised to switch to the fixed 2.4.17 kernel-image
package for powerpc/apus from woody until the 2.4.20 kernel-image
package is fixed in the unstable distribution.

 Vulnerability matrix for CAN-2004-0077"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.2.10-powerpc-apus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.2.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/18");
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
if (deb_check(release:"3.0", prefix:"kernel-doc-2.2.10", reference:"2.2.10-2")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.2.10-apus", reference:"2.2.10-13woody1")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.2.10-apus", reference:"2.2.10-13woody1")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-source-2.2.10", reference:"2.2.10-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
