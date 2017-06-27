#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1539. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31809);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/05/03 11:14:59 $");

  script_cve_id("CVE-2007-4542", "CVE-2007-4629");
  script_xref(name:"DSA", value:"1539");

  script_name(english:"Debian DSA-1539-1 : mapserver - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Schmidt and Daniel Morissette discovered two vulnerabilities in
mapserver, a development environment for spatial and mapping
applications. The Common Vulnerabilities and Exposures project
identifies the following two problems :

  - CVE-2007-4542
    Lack of input sanitizing and output escaping in the CGI
    mapserver's template handling and error reporting
    routines leads to cross-site scripting vulnerabilities.

  - CVE-2007-4629
    Missing bounds checking in mapserver's template handling
    leads to a stack-based buffer overrun vulnerability,
    allowing a remote attacker to execute arbitrary code
    with the privileges of the CGI or httpd user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1539"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mapserver (4.10.0-5.1+etch2) package.

For the stable distribution (etch), these problems have been fixed in
version 4.10.0-5.1+etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mapserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/11");
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
if (deb_check(release:"4.0", prefix:"cgi-mapserver", reference:"4.10.0-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"mapserver-bin", reference:"4.10.0-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"mapserver-doc", reference:"4.10.0-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"perl-mapscript", reference:"4.10.0-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mapscript", reference:"4.10.0-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mapscript", reference:"4.10.0-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"python-mapscript", reference:"4.10.0-5.1+etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
