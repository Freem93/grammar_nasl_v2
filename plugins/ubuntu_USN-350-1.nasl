#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-350-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27930);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2001-0734", "CVE-2006-3113", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3804", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811", "CVE-2006-3812", "CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4567", "CVE-2006-4570", "CVE-2006-4571", "CVE-2006-5462", "CVE-2007-1794");
  script_bugtraq_id(19849, 20042);
  script_osvdb_id(7560, 27561, 27562, 27563, 27564, 27565, 27566, 27568, 27569, 27570, 27571, 27572, 27573, 27574, 27575, 27576, 27577, 27974, 27975, 28843, 28844, 28845, 28848, 29012, 29013, 94469, 94470, 94471, 94472, 94473, 94474, 94475, 94476, 94477, 94478, 94479, 94480, 95338, 95339, 95340, 95341, 95911, 95912, 95913, 95914, 95915, 96645);
  script_xref(name:"USN", value:"350-1");

  script_name(english:"Ubuntu 5.10 : mozilla-thunderbird vulnerabilities (USN-350-1)");
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
"This update upgrades Thunderbird from 1.0.8 to 1.5.0.7. This step was
necessary since the 1.0.x series is not supported by upstream any
more.

Various flaws have been reported that allow an attacker to execute
arbitrary code with user privileges by tricking the user into opening
a malicious email containing JavaScript. Please note that JavaScript
is disabled by default for emails, and it is not recommended to enable
it. (CVE-2006-3113, CVE-2006-3802, CVE-2006-3803, CVE-2006-3805,
CVE-2006-3806, CVE-2006-3807, CVE-2006-3809, CVE-2006-3810,
CVE-2006-3811, CVE-2006-3812, CVE-2006-4253, CVE-2006-4565,
CVE-2006-4566, CVE-2006-4571)

A buffer overflow has been discovered in the handling of .vcard files.
By tricking a user into importing a malicious vcard into his contacts,
this could be exploited to execute arbitrary code with the user's
privileges. (CVE-2006-3804)

The NSS library did not sufficiently check the padding of PKCS #1 v1.5
signatures if the exponent of the public key is 3 (which is widely
used for CAs). This could be exploited to forge valid signatures
without the need of the secret key. (CVE-2006-4340)

Jon Oberheide reported a way how a remote attacker could trick users
into downloading arbitrary extensions with circumventing the normal
SSL certificate check. The attacker would have to be in a position to
spoof the victim's DNS, causing them to connect to sites of the
attacker's choosing rather than the sites intended by the victim. If
they gained that control and the victim accepted the attacker's cert
for the Mozilla update site, then the next update check could be
hijacked and redirected to the attacker's site without detection.
(CVE-2006-4567)

Georgi Guninski discovered that even with JavaScript disabled, a
malicous email could still execute JavaScript when the message is
viewed, replied to, or forwarded by putting the script in a remote XBL
file loaded by the message. (CVE-2006-4570)

The 'enigmail' plugin and the translation packages have been updated
to work with the new Thunderbird version.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-locale-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-locale-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-locale-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-locale-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-locale-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-locale-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-locale-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-typeaheadfind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.7-0ubuntu0.5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-dev", pkgver:"1.5.0.7-0ubuntu0.5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-enigmail", pkgver:"2:0.94-0ubuntu0.5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.5.0.7-0ubuntu0.5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-locale-ca", pkgver:"1.5-ubuntu5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-locale-de", pkgver:"1.5-ubuntu5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-locale-fr", pkgver:"1.5-ubuntu5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-locale-it", pkgver:"1.5-ubuntu5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-locale-nl", pkgver:"1.5-ubuntu5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-locale-pl", pkgver:"1.5-ubuntu5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-locale-uk", pkgver:"1.5-ubuntu5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.5.0.7-0ubuntu0.5.10")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-thunderbird / mozilla-thunderbird-dev / etc");
}
