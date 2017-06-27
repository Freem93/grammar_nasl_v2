#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-403. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15240);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/18 00:11:35 $");

  script_cve_id("CVE-2003-0961");
  script_bugtraq_id(9138);
  script_osvdb_id(2887);
  script_xref(name:"DSA", value:"403");

  script_name(english:"Debian DSA-403-1 : kernel-image-2.4.18-1-alpha, kernel-image-2.4.18-1-i386, kernel-source-2.4.18 - local root exploit");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Recently multiple servers of the Debian project were compromised using
a Debian developers account and an unknown root exploit. Forensics
revealed a burneye encrypted exploit. Robert van der Meulen managed to
decrypt the binary which revealed a kernel exploit. Study of the
exploit by the Red Hat and SuSE kernel and security teams quickly
revealed that the exploit used an integer overflow in the brk system
call. Using this bug it is possible for a userland program to trick
the kernel into giving access to the full kernel address space. This
problem was found in September by Andrew Morton, but unfortunately
that was too late for the 2.4.22 kernel release.

This bug has been fixed in kernel version 2.4.23 for the 2.4 tree and
2.6.0-test6 kernel tree. For Debian it has been fixed in version
2.4.18-14 of the kernel source packages, version 2.4.18-12 of the i386
kernel images and version 2.4.18-11 of the alpha kernel images."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-403"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected kernel-image-2.4.18-1-alpha, kernel-image-2.4.18-1-i386, and kernel-source-2.4.18 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.4.18-1-alpha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.4.18-1-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.4.18");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/12/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"kernel-doc-2.4.18", reference:"2.4.18-14")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-386", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-586tsc", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-686", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-686-smp", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-generic", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-k6", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-k7", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-smp", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-386", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-586tsc", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-686", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-686-smp", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-generic", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-k6", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-k7", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-smp", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-386", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-586tsc", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-686", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-686-smp", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-k6", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-k7", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-source-2.4.18", reference:"2.4.18-14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
