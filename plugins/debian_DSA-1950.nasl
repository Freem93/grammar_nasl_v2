#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1950. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44815);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-0945", "CVE-2009-1681", "CVE-2009-1684", "CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1692", "CVE-2009-1693", "CVE-2009-1694", "CVE-2009-1695", "CVE-2009-1697", "CVE-2009-1698", "CVE-2009-1710", "CVE-2009-1711", "CVE-2009-1712", "CVE-2009-1714", "CVE-2009-1725");
  script_osvdb_id(54455, 54500, 54981, 54985, 54987, 54991, 54992, 55004, 55005, 55006, 55014, 55015, 55022, 55023, 55242, 55414, 55417, 55418, 55739);
  script_xref(name:"DSA", value:"1950");

  script_name(english:"Debian DSA-1950-1 : webkit - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in WebKit, a Web content
engine library for Gtk+. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-0945
    Array index error in the insertItemBefore method in
    WebKit, allows remote attackers to execute arbitrary
    code via a document with a SVGPathList data structure
    containing a negative index in the SVGTransformList,
    SVGStringList, SVGNumberList, SVGPathSegList,
    SVGPointList, or SVGLengthList SVGList object, which
    triggers memory corruption.

  - CVE-2009-1687
    The JavaScript garbage collector in WebKit does not
    properly handle allocation failures, which allows remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted HTML document that triggers write access to an
    'offset of a NULL pointer.'

  - CVE-2009-1690
    Use-after-free vulnerability in WebKit, allows remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) by
    setting an unspecified property of an HTML tag that
    causes child elements to be freed and later accessed
    when an HTML error occurs, related to 'recursion in
    certain DOM event handlers.'

  - CVE-2009-1698
    WebKit does not initialize a pointer during handling of
    a Cascading Style Sheets (CSS) attr function call with a
    large numerical argument, which allows remote attackers
    to execute arbitrary code or cause a denial of service
    (memory corruption and application crash) via a crafted
    HTML document.

  - CVE-2009-1711
    WebKit does not properly initialize memory for Attr DOM
    objects, which allows remote attackers to execute
    arbitrary code or cause a denial of service (application
    crash) via a crafted HTML document.

  - CVE-2009-1712
    WebKit does not prevent remote loading of local Java
    applets, which allows remote attackers to execute
    arbitrary code, gain privileges, or obtain sensitive
    information via an APPLET or OBJECT element.

  - CVE-2009-1725
    WebKit do not properly handle numeric character
    references, which allows remote attackers to execute
    arbitrary code or cause a denial of service (memory
    corruption and application crash) via a crafted HTML
    document.

  - CVE-2009-1714
    Cross-site scripting (XSS) vulnerability in Web
    Inspector in WebKit allows user-assisted remote
    attackers to inject arbitrary web script or HTML, and
    read local files, via vectors related to the improper
    escaping of HTML attributes.

  - CVE-2009-1710
    WebKit allows remote attackers to spoof the browser's
    display of the host name, security indicators, and
    unspecified other UI elements via a custom cursor in
    conjunction with a modified CSS3 hotspot property.

  - CVE-2009-1697
    CRLF injection vulnerability in WebKit allows remote
    attackers to inject HTTP headers and bypass the Same
    Origin Policy via a crafted HTML document, related to
    cross-site scripting (XSS) attacks that depend on
    communication with arbitrary websites on the same server
    through use of XMLHttpRequest without a Host header.

  - CVE-2009-1695
    Cross-site scripting (XSS) vulnerability in WebKit
    allows remote attackers to inject arbitrary web script
    or HTML via vectors involving access to frame contents
    after completion of a page transition.

  - CVE-2009-1693
    WebKit allows remote attackers to read images from
    arbitrary websites via a CANVAS element with an SVG
    image, related to a 'cross-site image capture issue.'

  - CVE-2009-1694
    WebKit does not properly handle redirects, which allows
    remote attackers to read images from arbitrary websites
    via vectors involving a CANVAS element and redirection,
    related to a 'cross-site image capture issue.'

  - CVE-2009-1681
    WebKit does not prevent websites from loading
    third-party content into a subframe, which allows remote
    attackers to bypass the Same Origin Policy and conduct
    'clickjacking' attacks via a crafted HTML document.

  - CVE-2009-1684
    Cross-site scripting (XSS) vulnerability in WebKit
    allows remote attackers to inject arbitrary web script
    or HTML via an event handler that triggers script
    execution in the context of the next loaded document.

  - CVE-2009-1692
    WebKit allows remote attackers to cause a denial of
    service (memory consumption or device reset) via a web
    page containing an HTMLSelectElement object with a large
    length attribute, related to the length property of a
    Select object."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=532724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=532725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=534946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=535793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=538346"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1950"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the webkit package.

For the stable distribution (lenny), these problems has been fixed in
version 1.0.1-4+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 94, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/12");
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
if (deb_check(release:"5.0", prefix:"libwebkit-1.0-1", reference:"1.0.1-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libwebkit-1.0-1-dbg", reference:"1.0.1-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libwebkit-dev", reference:"1.0.1-4+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
