#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1914. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44779);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-0839", "CVE-2009-0840", "CVE-2009-0841", "CVE-2009-0842", "CVE-2009-0843", "CVE-2009-2281");
  script_osvdb_id(56329, 56330, 56331, 56332, 56333, 59284);
  script_xref(name:"DSA", value:"1914");

  script_name(english:"Debian DSA-1914-1 : mapserver - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in mapserver, a CGI-based
web framework to publish spatial data and interactive mapping
applications. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2009-0843
    Missing input validation on a user-supplied map
    queryfile name can be used by an attacker to check for
    the existence of a specific file by using the queryfile
    GET parameter and checking for differences in error
    messages.

  - CVE-2009-0842
    A lack of file type verification when parsing a map file
    can lead to partial disclosure of content from arbitrary
    files through parser error messages.

  - CVE-2009-0841
    Due to missing input validation when saving map files
    under certain conditions it is possible to perform
    directory traversal attacks and to create arbitrary
    files. NOTE: Unless the attacker is able to create
    directories in the image path or there is already a
    readable directory this doesn't affect installations on
    Linux as the fopen() syscall will fail in case a sub
    path is not readable.

  - CVE-2009-0839
    It was discovered that mapserver is vulnerable to a
    stack-based buffer overflow when processing certain GET
    parameters. An attacker can use this to execute
    arbitrary code on the server via crafted id parameters.

  - CVE-2009-0840
    An integer overflow leading to a heap-based buffer
    overflow when processing the Content-Length header of an
    HTTP request can be used by an attacker to execute
    arbitrary code via crafted POST requests containing
    negative Content-Length values.

  - CVE-2009-2281
    An integer overflow when processing HTTP requests can
    lead to a heap-based buffer overflow. An attacker can
    use this to execute arbitrary code either via crafted
    Content-Length values or large HTTP request. This is
    partly because of an incomplete fix for CVE-2009-0840."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1914"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mapserver packages.

For the oldstable distribution (etch), this problem has been fixed in
version 4.10.0-5.1+etch4.

For the stable distribution (lenny), this problem has been fixed in
version 5.0.3-3+lenny4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 22, 119, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mapserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"cgi-mapserver", reference:"4.10.0-5.1+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"mapserver-bin", reference:"4.10.0-5.1+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"mapserver-doc", reference:"4.10.0-5.1+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"perl-mapscript", reference:"4.10.0-5.1+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mapscript", reference:"4.10.0-5.1+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mapscript", reference:"4.10.0-5.1+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"python-mapscript", reference:"4.10.0-5.1+etch4")) flag++;
if (deb_check(release:"5.0", prefix:"cgi-mapserver", reference:"5.0.3-3+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libmapscript-ruby", reference:"5.0.3-3+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libmapscript-ruby1.8", reference:"5.0.3-3+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libmapscript-ruby1.9", reference:"5.0.3-3+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"mapserver-bin", reference:"5.0.3-3+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"mapserver-doc", reference:"5.0.3-3+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"perl-mapscript", reference:"5.0.3-3+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mapscript", reference:"5.0.3-3+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"python-mapscript", reference:"5.0.3-3+lenny4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
