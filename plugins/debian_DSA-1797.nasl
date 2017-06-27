#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1797. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38724);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-0652", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1311");
  script_xref(name:"DSA", value:"1797");

  script_name(english:"Debian DSA-1797-1 : xulrunner - several vulnerabilities");
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

  - CVE-2009-0652
    Moxie Marlinspike discovered that Unicode box drawing
    characters inside of internationalised domain names
    could be used for phishing attacks.

  - CVE-2009-1302
    Olli Pettay, Martijn Wargers, Mats Palmgren, Oleg
    Romashin, Jesse Ruderman and Gary Kwong reported crashes
    in the layout engine, which might allow the execution of
    arbitrary code.

  - CVE-2009-1303
    Olli Pettay, Martijn Wargers, Mats Palmgren, Oleg
    Romashin, Jesse Ruderman and Gary Kwong reported crashes
    in the layout engine, which might allow the execution of
    arbitrary code.

  - CVE-2009-1304
    Igor Bukanov and Bob Clary discovered crashes in the
    JavaScript engine, which might allow the execution of
    arbitrary code.

  - CVE-2009-1305
    Igor Bukanov and Bob Clary discovered crashes in the
    JavaScript engine, which might allow the execution of
    arbitrary code.

  - CVE-2009-1306
    Daniel Veditz discovered that the Content-Disposition:
    header is ignored within the jar: URI scheme.

  - CVE-2009-1307
    Gregory Fleischer discovered that the same-origin policy
    for Flash files is inproperly enforced for files loaded
    through the view-source scheme, which may result in
    bypass of cross-domain policy restrictions.

  - CVE-2009-1308
    Cefn Hoile discovered that sites, which allow the
    embedding of third-party stylesheets are vulnerable to
    cross-site scripting attacks through XBL bindings.

  - CVE-2009-1309
    'moz_bug_r_a4' discovered bypasses of the same-origin
    policy in the XMLHttpRequest JavaScript API and the
    XPCNativeWrapper.

  - CVE-2009-1311
    Paolo Amadini discovered that incorrect handling of POST
    data when saving a website with an embedded frame may
    lead to information disclosure.

  - CVE-2009-1312
    It was discovered that Iceweasel allows Refresh: headers
    to redirect to JavaScript URIs, resulting in cross-site
    scripting."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1797"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xulrunner packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.9-0lenny2.

As indicated in the Etch release notes, security support for the
Mozilla products in the oldstable distribution needed to be stopped
before the end of the regular Etch security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a still
supported browser."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 79, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/11");
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
if (deb_check(release:"5.0", prefix:"libmozillainterfaces-java", reference:"1.9.0.9-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs-dev", reference:"1.9.0.9-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d", reference:"1.9.0.9-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d-dbg", reference:"1.9.0.9-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"python-xpcom", reference:"1.9.0.9-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"spidermonkey-bin", reference:"1.9.0.9-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9", reference:"1.9.0.9-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-dbg", reference:"1.9.0.9-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-gnome-support", reference:"1.9.0.9-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-dev", reference:"1.9.0.9-0lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
