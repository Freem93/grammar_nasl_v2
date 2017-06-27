#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-818. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19787);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-2101");
  script_xref(name:"DSA", value:"818");

  script_name(english:"Debian DSA-818-1 : kdeedu - insecure temporary files");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Javier Fernandez-Sanguino Pena discovered that langen2kvhtml from
the kvoctrain package from the kdeedu suite creates temporary files in
an insecure fashion. This leaves them open for symlink attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-818"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kvoctrain package.

The old stable distribution (woody) is not affected by these problems.

For the stable distribution (sarge) these problems have been fixed in
version 3.3.2-3.sarge.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdeedu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"kalzium", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kbruch", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kdeedu", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kdeedu-data", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kdeedu-doc-html", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"keduca", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"khangman", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kig", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kiten", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"klatin", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"klettres", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"klettres-data", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kmessedwords", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kmplot", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kpercentage", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kstars", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kstars-data", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"ktouch", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kturtle", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kverbos", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kvoctrain", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kwordquiz", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"libkdeedu-dev", reference:"3.3.2-3.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"libkdeedu1", reference:"3.3.2-3.sarge.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
