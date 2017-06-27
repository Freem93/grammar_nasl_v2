#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1988. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44852);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-0945", "CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698", "CVE-2009-1699", "CVE-2009-1711", "CVE-2009-1712", "CVE-2009-1713", "CVE-2009-1725", "CVE-2009-2700");
  script_bugtraq_id(34924, 35271, 35309, 35318);
  script_osvdb_id(54455, 54500, 54972, 54975, 54985, 55006, 55015, 55022, 55414, 55417, 55418, 55739, 57633);
  script_xref(name:"DSA", value:"1988");

  script_name(english:"Debian DSA-1988-1 : qt4-x11 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in qt4-x11, a
cross-platform C++ application framework. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2009-0945
    Array index error in the insertItemBefore method in
    WebKit, as used in qt4-x11, allows remote attackers to
    execute arbitrary code.

  - CVE-2009-1687
    The JavaScript garbage collector in WebKit, as used in
    qt4-x11 does not properly handle allocation failures,
    which allows remote attackers to execute arbitrary code
    or cause a denial of service (memory corruption and
    application crash) via a crafted HTML document that
    triggers write access to an 'offset of a NULL pointer.

  - CVE-2009-1690
    Use-after-free vulnerability in WebKit, as used in
    qt4-x11, allows remote attackers to execute arbitrary
    code or cause a denial of service (memory corruption and
    application crash) by setting an unspecified property of
    an HTML tag that causes child elements to be freed and
    later accessed when an HTML error occurs.

  - CVE-2009-1698
    WebKit in qt4-x11 does not initialize a pointer during
    handling of a Cascading Style Sheets (CSS) attr function
    call with a large numerical argument, which allows
    remote attackers to execute arbitrary code or cause a
    denial of service (memory corruption and application
    crash) via a crafted HTML document.

  - CVE-2009-1699
    The XSL stylesheet implementation in WebKit, as used in
    qt4-x11 does not properly handle XML external entities,
    which allows remote attackers to read arbitrary files
    via a crafted DTD.

  - CVE-2009-1711
    WebKit in qt4-x11 does not properly initialize memory
    for Attr DOM objects, which allows remote attackers to
    execute arbitrary code or cause a denial of service
    (application crash) via a crafted HTML document.

  - CVE-2009-1712
    WebKit in qt4-x11 does not prevent remote loading of
    local Java applets, which allows remote attackers to
    execute arbitrary code, gain privileges, or obtain
    sensitive information via an APPLET or OBJECT element.

  - CVE-2009-1713
    The XSLT functionality in WebKit, as used in qt4-x11
    does not properly implement the document function, which
    allows remote attackers to read arbitrary local files
    and files from different security zones.

  - CVE-2009-1725
    WebKit in qt4-x11 does not properly handle numeric
    character references, which allows remote attackers to
    execute arbitrary code or cause a denial of service
    (memory corruption and application crash) via a crafted
    HTML document.

  - CVE-2009-2700
    qt4-x11 does not properly handle a '\0' character in a
    domain name in the Subject Alternative Name field of an
    X.509 certificate, which allows man-in-the-middle
    attackers to spoof arbitrary SSL servers via a crafted
    certificate issued by a legitimate Certification
    Authority.

The oldstable distribution (etch) is not affected by these problems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=532718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=534946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=538347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=545793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1988"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qt4-x11 packages.

For the stable distribution (lenny), these problems have been fixed in
version 4.4.3-1+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/02");
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
if (deb_check(release:"5.0", prefix:"libqt4-assistant", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-core", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-dbg", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-dbus", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-designer", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-dev", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-gui", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-help", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-network", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-opengl", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-opengl-dev", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-qt3support", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-script", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-sql", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-sql-ibase", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-sql-mysql", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-sql-odbc", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-sql-psql", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-sql-sqlite", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-sql-sqlite2", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-svg", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-test", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-webkit", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-webkit-dbg", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-xml", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-xmlpatterns", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqt4-xmlpatterns-dbg", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqtcore4", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libqtgui4", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"qt4-demos", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"qt4-designer", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"qt4-dev-tools", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"qt4-doc", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"qt4-doc-html", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"qt4-qmake", reference:"4.4.3-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"qt4-qtconfig", reference:"4.4.3-1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
