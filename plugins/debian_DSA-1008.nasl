#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1008. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22550);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/03 11:14:57 $");

  script_cve_id("CVE-2006-0746");
  script_osvdb_id(23833);
  script_xref(name:"DSA", value:"1008");

  script_name(english:"Debian DSA-1008-1 : kdegraphics - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Marcelo Ricardo Leitner noticed that the current patch in DSA
932(CVE-2005-3627 ) for kpdf, the PDF viewer for KDE, does not fix all
buffer overflows, still allowing an attacker to execute arbitrary
code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1008"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kpdf package.

The old stable distribution (woody) does not contain kpdf packages.

For the stable distribution (sarge) this problem has been fixed in
version 3.3.2-2sarge4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"kamera", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kcoloredit", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kdegraphics", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kdegraphics-dev", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kdegraphics-kfile-plugins", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kdvi", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kfax", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kgamma", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kghostview", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kiconedit", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kmrml", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kolourpaint", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kooka", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kpdf", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kpovmodeler", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kruler", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"ksnapshot", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"ksvg", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kuickshow", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kview", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kviewshell", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"libkscan-dev", reference:"3.3.2-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"libkscan1", reference:"3.3.2-2sarge4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
