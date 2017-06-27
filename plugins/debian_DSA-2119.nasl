#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2119. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49965);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/05/17 23:58:35 $");

  script_cve_id("CVE-2010-3702", "CVE-2010-3704");
  script_osvdb_id(69062, 69064);
  script_xref(name:"DSA", value:"2119");

  script_name(english:"Debian DSA-2119-1 : poppler - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Joel Voss of Leviathan Security Group discovered two vulnerabilities
in the Poppler PDF rendering library, which may lead to the execution
of arbitrary code if a malformed PDF file is opened."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=599165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2119"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the poppler packages.

For the stable distribution (lenny), these problems have been fixed in
version 0.8.7-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poppler");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libpoppler-dev", reference:"0.8.7-4")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler-glib-dev", reference:"0.8.7-4")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler-glib3", reference:"0.8.7-4")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler-qt-dev", reference:"0.8.7-4")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler-qt2", reference:"0.8.7-4")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler-qt4-3", reference:"0.8.7-4")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler-qt4-dev", reference:"0.8.7-4")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler3", reference:"0.8.7-4")) flag++;
if (deb_check(release:"5.0", prefix:"poppler-dbg", reference:"0.8.7-4")) flag++;
if (deb_check(release:"5.0", prefix:"poppler-utils", reference:"0.8.7-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
