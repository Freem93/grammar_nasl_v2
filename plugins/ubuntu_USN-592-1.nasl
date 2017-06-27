#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-592-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31700);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2007-4879", "CVE-2008-0416", "CVE-2008-1195", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241");
  script_bugtraq_id(28448);
  script_osvdb_id(42601, 43846, 43847, 43848, 43849, 43857, 43858, 43859, 43860, 43861, 43862, 43863, 43864, 43865, 43866, 43867, 43868, 43869, 43870, 43871, 43872, 43873, 43874, 43875, 43876, 43877, 43878);
  script_xref(name:"USN", value:"592-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : firefox vulnerabilities (USN-592-1)");
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
"Alexey Proskuryakov, Yosuke Hasegawa and Simon Montagu discovered
flaws in Firefox's character encoding handling. If a user were tricked
into opening a malicious web page, an attacker could perform
cross-site scripting attacks. (CVE-2008-0416)

Various flaws were discovered in the JavaScript engine. By tricking a
user into opening a malicious web page, an attacker could escalate
privileges within the browser, perform cross-site scripting attacks
and/or execute arbitrary code with the user's privileges.
(CVE-2008-1233, CVE-2008-1234, CVE-2008-1235)

Several problems were discovered in Firefox which could lead to
crashes and memory corruption. If a user were tricked into opening a
malicious web page, an attacker may be able to execute arbitrary code
with the user's privileges. (CVE-2008-1236, CVE-2008-1237)

Gregory Fleischer discovered Firefox did not properly process HTTP
Referrer headers when they were sent with with requests to URLs
containing Basic Authentication credentials with empty usernames. An
attacker could exploit this vulnerability to perform cross-site
request forgery attacks. (CVE-2008-1238)

Peter Brodersen and Alexander Klink reported that default the setting
in Firefox for SSL Client Authentication allowed for users to be
tracked via their client certificate. The default has been changed to
prompt the user each time a website requests a client certificate.
(CVE-2007-4879)

Gregory Fleischer discovered that web content fetched via the jar
protocol could use Java LiveConnect to connect to arbitrary ports on
the user's machine due to improper parsing in the Java plugin. If a
user were tricked into opening malicious web content, an attacker may
be able to access services running on the user's machine.
(CVE-2008-1195, CVE-2008-1240)

Chris Thomas discovered that Firefox would allow an XUL popup from an
unselected tab to display in front of the selected tab. An attacker
could exploit this behavior to spoof a login prompt and steal the
user's credentials. (CVE-2008-1241).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 79, 94, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-libthai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"firefox", pkgver:"1.5.dfsg+1.5.0.15~prepatch080323a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dbg", pkgver:"1.5.dfsg+1.5.0.15~prepatch080323a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dev", pkgver:"1.5.dfsg+1.5.0.15~prepatch080323a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dom-inspector", pkgver:"1.5.dfsg+1.5.0.15~prepatch080323a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-gnome-support", pkgver:"1.5.dfsg+1.5.0.15~prepatch080323a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnspr-dev", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080323a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnspr4", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080323a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnss-dev", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080323a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnss3", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080323a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-firefox", pkgver:"1.5.dfsg+1.5.0.15~prepatch080323a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-firefox-dev", pkgver:"1.5.dfsg+1.5.0.15~prepatch080323a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-dbg", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-dev", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-dom-inspector", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-gnome-support", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnspr-dev", pkgver:"1.firefox2.0.0.13+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnspr4", pkgver:"1.firefox2.0.0.13+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnss-dev", pkgver:"1.firefox2.0.0.13+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnss3", pkgver:"1.firefox2.0.0.13+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox-dev", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox-dom-inspector", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox-gnome-support", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-dbg", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-dev", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-dom-inspector", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-gnome-support", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-libthai", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnspr-dev", pkgver:"1.firefox2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnspr4", pkgver:"1.firefox2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnss-dev", pkgver:"1.firefox2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnss3", pkgver:"1.firefox2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox-dev", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox-dom-inspector", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox-gnome-support", pkgver:"2.0.0.13+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox", pkgver:"2.0.0.13+1nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-dbg", pkgver:"2.0.0.13+1nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-dev", pkgver:"2.0.0.13+1nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-dom-inspector", pkgver:"2.0.0.13+1nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-gnome-support", pkgver:"2.0.0.13+1nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-libthai", pkgver:"2.0.0.13+1nobinonly-0ubuntu0.7.10")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-dbg / firefox-dev / firefox-dom-inspector / etc");
}
