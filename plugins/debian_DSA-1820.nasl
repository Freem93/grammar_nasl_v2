#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1820. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39452);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841");
  script_bugtraq_id(35360, 35370, 35371, 35372, 35373, 35377, 35380, 35383, 35386, 35388, 35391);
  script_xref(name:"DSA", value:"1820");

  script_name(english:"Debian DSA-1820-1 : xulrunner - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications, such as the Iceweasel web
browser. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2009-1392
    Several issues in the browser engine have been
    discovered, which can result in the execution of
    arbitrary code. (MFSA 2009-24)

  - CVE-2009-1832
    It is possible to execute arbitrary code via vectors
    involving 'double frame construction.' (MFSA 2009-24)

  - CVE-2009-1833
    Jesse Ruderman and Adam Hauner discovered a problem in
    the JavaScript engine, which could lead to the execution
    of arbitrary code. (MFSA 2009-24)

  - CVE-2009-1834
    Pavel Cvrcek discovered a potential issue leading to a
    spoofing attack on the location bar related to certain
    invalid unicode characters. (MFSA 2009-25)

  - CVE-2009-1835
    Gregory Fleischer discovered that it is possible to read
    arbitrary cookies via a crafted HTML document. (MFSA
    2009-26)

  - CVE-2009-1836
    Shuo Chen, Ziqing Mao, Yi-Min Wang and Ming Zhang
    reported a potential man-in-the-middle attack, when
    using a proxy due to insufficient checks on a certain
    proxy response. (MFSA 2009-27)

  - CVE-2009-1837
    Jakob Balle and Carsten Eiram reported a race condition
    in the NPObjWrapper_NewResolve function that can be used
    to execute arbitrary code. (MFSA 2009-28)

  - CVE-2009-1838
    moz_bug_r_a4 discovered that it is possible to execute
    arbitrary JavaScript with chrome privileges due to an
    error in the garbage-collection implementation. (MFSA
    2009-29)

  - CVE-2009-1839
    Adam Barth and Collin Jackson reported a potential
    privilege escalation when loading a file::resource via
    the location bar. (MFSA 2009-30)

  - CVE-2009-1840
    Wladimir Palant discovered that it is possible to bypass
    access restrictions due to a lack of content policy
    check, when loading a script file into a XUL document.
    (MFSA 2009-31)

  - CVE-2009-1841
    moz_bug_r_a4 reported that it is possible for scripts
    from page content to run with elevated privileges and
    thus potentially executing arbitrary code with the
    object's chrome privileges. (MFSA 2009-32)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1820"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xulrunner packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.11-0lenny1.

As indicated in the Etch release notes, security support for the
Mozilla products in the oldstable distribution needed to be stopped
before the end of the regular Etch security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a still
supported browser."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 200, 264, 287, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libmozillainterfaces-java", reference:"1.9.0.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs-dev", reference:"1.9.0.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d", reference:"1.9.0.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d-dbg", reference:"1.9.0.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python-xpcom", reference:"1.9.0.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"spidermonkey-bin", reference:"1.9.0.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9", reference:"1.9.0.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-dbg", reference:"1.9.0.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-gnome-support", reference:"1.9.0.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-dev", reference:"1.9.0.11-0lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
