#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-576-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30252);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
  script_osvdb_id(41187, 41215, 41217, 41218, 41220, 41221, 41222, 41223, 41224, 43226, 43456, 43457, 43458, 43459, 43460, 43461, 43462);
  script_xref(name:"USN", value:"576-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : firefox vulnerabilities (USN-576-1)");
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
"Various flaws were discovered in the browser and JavaScript engine. By
tricking a user into opening a malicious web page, an attacker could
execute arbitrary code with the user's privileges. (CVE-2008-0412,
CVE-2008-0413)

Flaws were discovered in the file upload form control. A malicious
website could force arbitrary files from the user's computer to be
uploaded without consent. (CVE-2008-0414)

Various flaws were discovered in the JavaScript engine. By tricking a
user into opening a malicious web page, an attacker could escalate
privileges within the browser, perform cross-site scripting attacks
and/or execute arbitrary code with the user's privileges.
(CVE-2008-0415)

Various flaws were discovered in character encoding handling. If a
user were ticked into opening a malicious web page, an attacker could
perform cross-site scripting attacks. (CVE-2008-0416)

Justin Dolske discovered a flaw in the password saving mechanism. By
tricking a user into opening a malicious web page, an attacker could
corrupt the user's stored passwords. (CVE-2008-0417)

Gerry Eisenhaur discovered that the chrome URI scheme did not properly
guard against directory traversal. Under certain circumstances, an
attacker may be able to load files or steal session data. Ubuntu is
not vulnerable in the default installation. (CVE-2008-0418)

David Bloom discovered flaws in the way images are treated by the
browser. A malicious website could exploit this to steal the user's
history information, crash the browser and/or possibly execute
arbitrary code with the user's privileges. (CVE-2008-0419)

Flaws were discovered in the BMP decoder. By tricking a user into
opening a specially crafted BMP file, an attacker could obtain
sensitive information. (CVE-2008-0420)

Michal Zalewski discovered flaws with timer-enabled security dialogs.
A malicious website could force the user to confirm a security dialog
without explicit consent. (CVE-2008-0591)

It was discovered that Firefox mishandled locally saved plain text
files. By tricking a user into saving a specially crafted text file,
an attacker could prevent the browser from displaying local files with
a .txt extension. (CVE-2008-0592)

Martin Straka discovered flaws in stylesheet handling after a 302
redirect. By tricking a user into opening a malicious web page, an
attacker could obtain sensitive URL parameters. (CVE-2008-0593)

Emil Ljungdahl and Lars-Olof Moilanen discovered that a web forgery
warning dialog wasn't displayed under certain circumstances. A
malicious website could exploit this to conduct phishing attacks
against the user. (CVE-2008-0594).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 22, 79, 94, 200, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");
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

if (ubuntu_check(osver:"6.06", pkgname:"firefox", pkgver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dbg", pkgver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dev", pkgver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dom-inspector", pkgver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-gnome-support", pkgver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnspr-dev", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnspr4", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnss-dev", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnss3", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-firefox", pkgver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-firefox-dev", pkgver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox", pkgver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-dbg", pkgver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-dev", pkgver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-dom-inspector", pkgver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-gnome-support", pkgver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnspr-dev", pkgver:"1.firefox2.0.0.12+0nobinonly+2-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnspr4", pkgver:"1.firefox2.0.0.12+0nobinonly+2-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnss-dev", pkgver:"1.firefox2.0.0.12+0nobinonly+2-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnss3", pkgver:"1.firefox2.0.0.12+0nobinonly+2-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox", pkgver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox-dev", pkgver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox-dom-inspector", pkgver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox-gnome-support", pkgver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox", pkgver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-dbg", pkgver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-dev", pkgver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-dom-inspector", pkgver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-gnome-support", pkgver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-libthai", pkgver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnspr-dev", pkgver:"1.firefox2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnspr4", pkgver:"1.firefox2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnss-dev", pkgver:"1.firefox2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnss3", pkgver:"1.firefox2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox", pkgver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox-dev", pkgver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox-dom-inspector", pkgver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox-gnome-support", pkgver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox", pkgver:"2.0.0.12+2nobinonly+2-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-dbg", pkgver:"2.0.0.12+2nobinonly+2-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-dev", pkgver:"2.0.0.12+2nobinonly+2-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-dom-inspector", pkgver:"2.0.0.12+2nobinonly+2-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-gnome-support", pkgver:"2.0.0.12+2nobinonly+2-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-libthai", pkgver:"2.0.0.12+2nobinonly+2-0ubuntu0.7.10")) flag++;

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
