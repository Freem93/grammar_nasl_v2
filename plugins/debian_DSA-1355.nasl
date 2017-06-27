#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1355. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25936);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/17 23:41:28 $");

  script_cve_id("CVE-2007-3387");
  script_osvdb_id(38120);
  script_xref(name:"DSA", value:"1355");

  script_name(english:"Debian DSA-1355-1 : kdegraphics - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that an integer overflow in the xpdf PDF viewer may
lead to the execution of arbitrary code if a malformed PDF file is
opened.

kpdf includes a copy of the xpdf code and required an update as well."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1355"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kpdf packages.

For the oldstable distribution (sarge) this problem has been fixed in
version 3.3.2-2sarge5.

For the stable distribution (etch) this problem has been fixed in
version 3.5.5-3etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/30");
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
if (deb_check(release:"3.1", prefix:"kamera", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kcoloredit", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kdegraphics", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kdegraphics-dev", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kdegraphics-kfile-plugins", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kdvi", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kfax", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kgamma", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kghostview", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kiconedit", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kmrml", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kolourpaint", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kooka", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kpdf", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kpovmodeler", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kruler", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"ksnapshot", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"ksvg", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kuickshow", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kview", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kviewshell", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libkscan-dev", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libkscan1", reference:"3.3.2-2sarge5")) flag++;
if (deb_check(release:"4.0", prefix:"kamera", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kcoloredit", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-dbg", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-dev", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-doc-html", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-kfile-plugins", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdvi", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kfax", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kfaxview", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kgamma", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kghostview", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kiconedit", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kmrml", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kolourpaint", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kooka", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kpdf", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kpovmodeler", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kruler", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ksnapshot", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ksvg", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kuickshow", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kview", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kviewshell", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libkscan-dev", reference:"3.5.5-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libkscan1", reference:"3.5.5-3etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
