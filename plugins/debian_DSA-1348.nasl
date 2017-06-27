#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1348. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25856);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/17 23:41:28 $");

  script_cve_id("CVE-2007-3387");
  script_osvdb_id(38120);
  script_xref(name:"DSA", value:"1348");

  script_name(english:"Debian DSA-1348-1 : poppler - integer overflow");
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

poppler includes a copy of the xpdf code and required an update as
well.

The oldstable distribution (sarge) doesn't include poppler."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1348"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the poppler packages.

For the stable distribution (etch) this problem has been fixed in
version 0.4.5-5.1etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poppler");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/13");
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
if (deb_check(release:"4.0", prefix:"libpoppler-dev", reference:"0.4.5-5.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpoppler-glib-dev", reference:"0.4.5-5.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpoppler-qt-dev", reference:"0.4.5-5.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpoppler0c2", reference:"0.4.5-5.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpoppler0c2-glib", reference:"0.4.5-5.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpoppler0c2-qt", reference:"0.4.5-5.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"poppler-utils", reference:"0.4.5-5.1etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
