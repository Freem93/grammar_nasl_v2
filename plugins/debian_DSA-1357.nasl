#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1357. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25937);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/17 23:41:28 $");

  script_cve_id("CVE-2007-3387");
  script_osvdb_id(38120);
  script_xref(name:"DSA", value:"1357");

  script_name(english:"Debian DSA-1357-1 : koffice - integer overflow");
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

koffice includes a copy of the xpdf code and required an update as
well.

The oldstable distribution (sarge) will be fixed later."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1357"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the koffice packages.

For the stable distribution (etch) this problem has been fixed in
version 1.6.1-2etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:koffice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/19");
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
if (deb_check(release:"4.0", prefix:"karbon", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kchart", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kexi", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kformula", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kivio", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kivio-data", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"koffice", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"koffice-data", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"koffice-dbg", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"koffice-dev", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"koffice-doc", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"koffice-doc-html", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"koffice-libs", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"koshell", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kplato", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kpresenter", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kpresenter-data", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"krita", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"krita-data", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kspread", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kthesaurus", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kugar", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kword", reference:"1.6.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kword-data", reference:"1.6.1-2etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
