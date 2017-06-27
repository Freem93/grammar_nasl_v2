#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1408. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28297);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/05/17 23:45:44 $");

  script_cve_id("CVE-2007-5393");
  script_osvdb_id(39541, 39542, 39543);
  script_xref(name:"DSA", value:"1408");

  script_name(english:"Debian DSA-1408-1 : kdegraphics - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Alin Rad Pop discovered a buffer overflow in kpdf, which could allow
the execution of arbitrary code if a malformed PDF file is displayed.

The old stable distribution (sarge) will be fixed later."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1408"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kdegraphics packages.

For the stable distribution (etch), this problem has been fixed in
version 4:3.5.5-3etch2. Builds for arm and sparc are not yet
available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"kamera", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kcoloredit", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-dbg", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-dev", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-doc-html", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-kfile-plugins", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kdvi", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kfax", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kfaxview", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kgamma", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kghostview", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kiconedit", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kmrml", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kolourpaint", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kooka", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kpdf", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kpovmodeler", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kruler", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"ksnapshot", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"ksvg", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kuickshow", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kview", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kviewshell", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libkscan-dev", reference:"4:3.5.5-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libkscan1", reference:"4:3.5.5-3etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
