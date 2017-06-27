#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1548. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32003);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/05/03 11:14:59 $");

  script_cve_id("CVE-2008-1693");
  script_osvdb_id(44434);
  script_xref(name:"DSA", value:"1548");

  script_name(english:"Debian DSA-1548-1 : xpdf - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Kees Cook discovered a vulnerability in xpdf, a set of tools for
display and conversion of Portable Document Format (PDF) files. The
Common Vulnerabilities and Exposures project identifies the following
problem :

  - CVE-2008-1693
    Xpdf's handling of embedded fonts lacks sufficient
    validation and type checking. If a maliciously crafted
    PDF file is opened, the vulnerability may allow the
    execution of arbitrary code with the privileges of the
    user running xpdf."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1548"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xpdf package.

For the stable distribution (etch), these problems have been fixed in
version 3.01-9.1+etch4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"xpdf", reference:"3.01-9.1+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"xpdf-common", reference:"3.01-9.1+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"xpdf-reader", reference:"3.01-9.1+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"xpdf-utils", reference:"3.01-9.1+etch4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
