#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-930-5. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47825);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2008-5913", "CVE-2010-0654", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203", "CVE-2010-1205", "CVE-2010-1206", "CVE-2010-1207", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1210", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213", "CVE-2010-1214", "CVE-2010-1215", "CVE-2010-2751", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754");
  script_bugtraq_id(33276, 38952, 40701, 41055, 41082, 41087, 41090, 41093, 41094, 41099, 41102, 41103, 41174, 41842, 41845, 41849, 41852, 41853, 41859, 41860, 41866, 41871, 41872, 41878);
  script_xref(name:"USN", value:"930-5");

  script_name(english:"Ubuntu 9.04 / 9.10 : ant, apturl, epiphany-browser, gluezilla, gnome-python-extras, liferea, mozvoikko, openjdk-6, packagekit, ubufox, webfav, yelp update (USN-930-5)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-930-4 fixed vulnerabilities in Firefox and Xulrunner on Ubuntu
9.04 and 9.10. This update provides updated packages for use with
Firefox 3.6 and Xulrunner 1.9.2.

If was discovered that Firefox could be made to access freed memory.
If a user were tricked into viewing a malicious site, a remote
attacker could cause a denial of service or possibly execute arbitrary
code with the privileges of the user invoking the program. This issue
only affected Ubuntu 8.04 LTS. (CVE-2010-1121)

Several flaws were discovered in the browser engine of
Firefox. If a user were tricked into viewing a malicious
site, a remote attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2010-1200, CVE-2010-1201,
CVE-2010-1202, CVE-2010-1203)

A flaw was discovered in the way plugin instances
interacted. An attacker could potentially exploit this and
use one plugin to access freed memory from a second plugin
to execute arbitrary code with the privileges of the user
invoking the program. (CVE-2010-1198)

An integer overflow was discovered in Firefox. If a user
were tricked into viewing a malicious site, an attacker
could overflow a buffer and cause a denial of service or
possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2010-1196)

Martin Barbella discovered an integer overflow in an XSLT
node sorting routine. An attacker could exploit this to
overflow a buffer and cause a denial of service or possibly
execute arbitrary code with the privileges of the user
invoking the program. (CVE-2010-1199)

Michal Zalewski discovered that the focus behavior of
Firefox could be subverted. If a user were tricked into
viewing a malicious site, a remote attacker could use this
to capture keystrokes. (CVE-2010-1125)

Ilja van Sprundel discovered that the 'Content-Disposition:
attachment' HTTP header was ignored when 'Content-Type:
multipart' was also present. Under certain circumstances,
this could potentially lead to cross-site scripting attacks.
(CVE-2010-1197)

Amit Klein discovered that Firefox did not seed its random
number generator often enough. An attacker could exploit
this to identify and track users across different websites.
(CVE-2008-5913)

Several flaws were discovered in the browser engine of
Firefox. If a user were tricked into viewing a malicious
site, a remote attacker could use this to crash the browser
or possibly run arbitrary code as the user invoking the
program. (CVE-2010-1208, CVE-2010-1209, CVE-2010-1211,
CVE-2010-1212)

An integer overflow was discovered in how Firefox processed
plugin parameters. An attacker could exploit this to crash
the browser or possibly run arbitrary code as the user
invoking the program. (CVE-2010-1214)

A flaw was discovered in the Firefox JavaScript engine. If a
user were tricked into viewing a malicious site, a remote
attacker code execute arbitrary JavaScript with chrome
privileges. (CVE-2010-1215)

An integer overflow was discovered in how Firefox processed
CSS values. An attacker could exploit this to crash the
browser or possibly run arbitrary code as the user invoking
the program. (CVE-2010-2752)

An integer overflow was discovered in how Firefox
interpreted the XUL <tree> element. If a user were tricked
into viewing a malicious site, a remote attacker could use
this to crash the browser or possibly run arbitrary code as
the user invoking the program. (CVE-2010-2753)

Aki Helin discovered that libpng did not properly handle
certain malformed PNG images. If a user were tricked into
opening a crafted PNG file, an attacker could cause a denial
of service or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2010-1205)

Yosuke Hasegawa and Vladimir Vukicevic discovered that the
same-origin check in Firefox could be bypassed by utilizing
the importScripts Web Worker method. If a user were tricked
into viewing a malicious website, an attacker could exploit
this to read data from other domains. (CVE-2010-1213,
CVE-2010-1207)

O. Andersen that Firefox did not properly map undefined
positions within certain 8 bit encodings. An attacker could
utilize this to perform cross-site scripting attacks.
(CVE-2010-1210)

Michal Zalewski discovered flaws in how Firefox processed
the HTTP 204 (no content) code. An attacker could exploit
this to spoof the location bar, such as in a phishing
attack. (CVE-2010-1206)

Jordi Chancel discovered that Firefox did not properly
handle when a server responds to an HTTPS request with
plaintext and then processes JavaScript history events. An
attacker could exploit this to spoof the location bar, such
as in a phishing attack. (CVE-2010-2751)

Chris Evans discovered that Firefox did not properly process
improper CSS selectors. If a user were tricked into viewing
a malicious website, an attacker could exploit this to read
data from other domains. (CVE-2010-0654)

Soroush Dalili discovered that Firefox did not properly
handle script error output. An attacker could use this to
access URL parameters from other domains. (CVE-2010-2754).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ant-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ant-gcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ant-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ant-optional-gcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apturl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-browser-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-browser-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-browser-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-gecko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-packagekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-cacao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea6-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgluezilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpackagekit-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpackagekit-glib11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpackagekit-qt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpackagekit-qt11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liferea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liferea-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-packagekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:packagekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:packagekit-backend-apt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:packagekit-backend-smart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:packagekit-backend-yum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-eggtrayicon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gksu2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gnome2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gnome2-extras-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gnome2-extras-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gnome2-extras-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gtkhtml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gtkmozembed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gtkspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-packagekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ubufox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:webfav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.04", pkgname:"ant", pkgver:"1.7.1-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ant-doc", pkgver:"1.7.1-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ant-gcj", pkgver:"1.7.1-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ant-optional", pkgver:"1.7.1-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ant-optional-gcj", pkgver:"1.7.1-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apturl", pkgver:"0.3.3ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"epiphany-browser", pkgver:"2.26.1-0ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"epiphany-browser-data", pkgver:"2.26.1-0ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"epiphany-browser-dbg", pkgver:"2.26.1-0ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"epiphany-browser-dev", pkgver:"2.26.1-0ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"epiphany-gecko", pkgver:"2.26.1-0ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"gstreamer0.10-packagekit", pkgver:"0.3.14-0ubuntu5.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b18-1.8-4ubuntu3~9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"icedtea6-plugin", pkgver:"6b18-1.8-4ubuntu3~9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libgluezilla", pkgver:"2.0-1ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpackagekit-glib-dev", pkgver:"0.3.14-0ubuntu5.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpackagekit-glib11", pkgver:"0.3.14-0ubuntu5.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpackagekit-qt-dev", pkgver:"0.3.14-0ubuntu5.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpackagekit-qt11", pkgver:"0.3.14-0ubuntu5.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"liferea", pkgver:"1.4.26-0ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"liferea-dbg", pkgver:"1.4.26-0ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mozilla-packagekit", pkgver:"0.3.14-0ubuntu5.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mozvoikko", pkgver:"0.9.5-1ubuntu2.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-dbg", pkgver:"6b18-1.8-4ubuntu3~9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-demo", pkgver:"6b18-1.8-4ubuntu3~9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-doc", pkgver:"6b18-1.8-4ubuntu3~9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jdk", pkgver:"6b18-1.8-4ubuntu3~9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre", pkgver:"6b18-1.8-4ubuntu3~9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b18-1.8-4ubuntu3~9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b18-1.8-4ubuntu3~9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b18-1.8-4ubuntu3~9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-source", pkgver:"6b18-1.8-4ubuntu3~9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"packagekit", pkgver:"0.3.14-0ubuntu5.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"packagekit-backend-apt", pkgver:"0.3.14-0ubuntu5.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"packagekit-backend-smart", pkgver:"0.3.14-0ubuntu5.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"packagekit-backend-yum", pkgver:"0.3.14-0ubuntu5.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-gnome2-extras", pkgver:"2.19.1-0ubuntu14.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-gnome2-extras-dbg", pkgver:"2.19.1-0ubuntu14.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-gnome2-extras-dev", pkgver:"2.19.1-0ubuntu14.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-gnome2-extras-doc", pkgver:"2.19.1-0ubuntu14.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-gtkhtml2", pkgver:"2.19.1-0ubuntu14.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-gtkhtml2-dbg", pkgver:"2.19.1-0ubuntu14.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-packagekit", pkgver:"0.3.14-0ubuntu5.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ubufox", pkgver:"0.9~rc2-0ubuntu0.9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"webfav", pkgver:"1.11-0ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"yelp", pkgver:"2.25.1-0ubuntu5.9.04.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ant", pkgver:"1.7.1-4ubuntu0.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ant-doc", pkgver:"1.7.1-4ubuntu0.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ant-gcj", pkgver:"1.7.1-4ubuntu0.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ant-optional", pkgver:"1.7.1-4ubuntu0.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ant-optional-gcj", pkgver:"1.7.1-4ubuntu0.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"icedtea-6-jre-cacao", pkgver:"6b18-1.8-4ubuntu3~9.10.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"icedtea6-plugin", pkgver:"6b18-1.8-4ubuntu3~9.10.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mozvoikko", pkgver:"1.0-1ubuntu3.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-dbg", pkgver:"6b18-1.8-4ubuntu3~9.10.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-demo", pkgver:"6b18-1.8-4ubuntu3~9.10.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-doc", pkgver:"6b18-1.8-4ubuntu3~9.10.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jdk", pkgver:"6b18-1.8-4ubuntu3~9.10.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre", pkgver:"6b18-1.8-4ubuntu3~9.10.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b18-1.8-4ubuntu3~9.10.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b18-1.8-4ubuntu3~9.10.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-zero", pkgver:"6b18-1.8-4ubuntu3~9.10.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-source", pkgver:"6b18-1.8-4ubuntu3~9.10.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-eggtrayicon", pkgver:"2.25.3-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-gda", pkgver:"2.25.3-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-gdl", pkgver:"2.25.3-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-gksu2", pkgver:"2.25.3-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-gnome2-extras", pkgver:"2.25.3-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-gnome2-extras-dbg", pkgver:"2.25.3-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-gnome2-extras-dev", pkgver:"2.25.3-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-gtkhtml2", pkgver:"2.25.3-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-gtkmozembed", pkgver:"2.25.3-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-gtkspell", pkgver:"2.25.3-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ubufox", pkgver:"0.9~rc2-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"webfav", pkgver:"1.16-0ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"yelp", pkgver:"2.28.0-0ubuntu2.9.10.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ant / ant-doc / ant-gcj / ant-optional / ant-optional-gcj / apturl / etc");
}
