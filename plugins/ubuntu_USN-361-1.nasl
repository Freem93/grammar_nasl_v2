#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-361-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27941);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/01 21:07:51 $");

  script_cve_id("CVE-2006-2788", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3811", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4568", "CVE-2006-4570", "CVE-2006-4571", "CVE-2006-5462", "CVE-2007-1794");
  script_bugtraq_id(19849, 20042);
  script_osvdb_id(27566, 27567, 27568, 27569, 27570, 27571, 27572, 27573, 27574, 27575, 27576, 27577, 27668, 28843, 28846, 28848, 29012, 29013, 94469, 94470, 94471, 94472, 94473, 94474, 94475, 94476, 94477, 94478, 94479, 94480, 95338, 95339, 95340, 95341, 95911, 95912, 95913, 95914, 95915, 96645);
  script_xref(name:"USN", value:"361-1");

  script_name(english:"Ubuntu 5.04 / 5.10 : mozilla vulnerabilities (USN-361-1)");
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
"Various flaws have been reported that allow an attacker to execute
arbitrary code with user privileges by tricking the user into opening
a malicious URL. (CVE-2006-2788, CVE-2006-3805, CVE-2006-3806,
CVE-2006-3807, CVE-2006-3809, CVE-2006-3811, CVE-2006-4565,
CVE-2006-4568, CVE-2006-4571)

A bug was found in the script handler for automatic proxy
configuration. A malicious proxy could send scripts which could
execute arbitrary code with the user's privileges. (CVE-2006-3808)

The NSS library did not sufficiently check the padding of PKCS #1 v1.5
signatures if the exponent of the public key is 3 (which is widely
used for CAs). This could be exploited to forge valid signatures
without the need of the secret key. (CVE-2006-4340)

Georgi Guninski discovered that even with JavaScript disabled, a
malicous email could still execute JavaScript when the message is
viewed, replied to, or forwarded by putting the script in a remote XBL
file loaded by the message. (CVE-2006-4570).

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
  script_cwe_id(20, 79, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-chatzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-mailnews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-psm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/27");
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
if (! ereg(pattern:"^(5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"libnspr-dev", pkgver:"1.7.13-0ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libnspr4", pkgver:"2:1.7.13-0ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libnss-dev", pkgver:"1.7.13-0ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libnss3", pkgver:"2:1.7.13-0ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla", pkgver:"1.7.13-0ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-browser", pkgver:"2:1.7.13-0ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-calendar", pkgver:"1.7.13-0ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-chatzilla", pkgver:"1.7.13-0ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-dev", pkgver:"1.7.13-0ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-dom-inspector", pkgver:"1.7.13-0ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-js-debugger", pkgver:"1.7.13-0ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-mailnews", pkgver:"2:1.7.13-0ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-psm", pkgver:"2:1.7.13-0ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libnspr-dev", pkgver:"1.7.13-0ubuntu5.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libnspr4", pkgver:"2:1.7.13-0ubuntu5.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libnss-dev", pkgver:"1.7.13-0ubuntu5.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libnss3", pkgver:"2:1.7.13-0ubuntu5.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla", pkgver:"1.7.13-0ubuntu5.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-browser", pkgver:"2:1.7.13-0ubuntu5.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-calendar", pkgver:"1.7.13-0ubuntu5.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-chatzilla", pkgver:"1.7.13-0ubuntu5.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-dev", pkgver:"1.7.13-0ubuntu5.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-dom-inspector", pkgver:"1.7.13-0ubuntu5.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-js-debugger", pkgver:"1.7.13-0ubuntu5.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-mailnews", pkgver:"2:1.7.13-0ubuntu5.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-psm", pkgver:"2:1.7.13-0ubuntu5.10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnspr-dev / libnspr4 / libnss-dev / libnss3 / mozilla / etc");
}
