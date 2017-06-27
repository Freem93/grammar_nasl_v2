#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3123-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94574);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2016-7141", "CVE-2016-7167", "CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8620", "CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624");
  script_osvdb_id(142493, 144213, 146565, 146567, 146568, 146569, 146570, 146571, 146572, 146573, 146574, 146575);
  script_xref(name:"USN", value:"3123-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : curl vulnerabilities (USN-3123-1)");
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
"It was discovered that curl incorrectly reused client certificates
when built with NSS. A remote attacker could possibly use this issue
to hijack the authentication of a TLS connection. (CVE-2016-7141)

Nguyen Vu Hoang discovered that curl incorrectly handled escaping
certain strings. A remote attacker could possibly use this issue to
cause curl to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-7167)

It was discovered that curl incorrectly handled storing cookies. A
remote attacker could possibly use this issue to inject cookies for
arbitrary domains in the cookie jar. (CVE-2016-8615)

It was discovered that curl incorrect handled case when comparing user
names and passwords. A remote attacker with knowledge of a
case-insensitive version of the correct password could possibly use
this issue to cause a connection to be reused. (CVE-2016-8616)

It was discovered that curl incorrect handled memory when encoding to
base64. A remote attacker could possibly use this issue to cause curl
to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-8617)

It was discovered that curl incorrect handled memory when preparing
formatted output. A remote attacker could possibly use this issue to
cause curl to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-8618)

It was discovered that curl incorrect handled memory when performing
Kerberos authentication. A remote attacker could possibly use this
issue to cause curl to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2016-8619)

Luat Nguyen discovered that curl incorrectly handled parsing
globs. A remote attacker could possibly use this issue to cause curl
to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 14.04 LTS, Ubuntu
16.04 LTS and Ubuntu 16.10. (CVE-2016-8620)

Luat Nguyen discovered that curl incorrectly handled converting
dates. A remote attacker could possibly use this issue to cause curl
to crash, resulting in a denial of service. (CVE-2016-8621)

It was discovered that curl incorrectly handled URL percent-encoding
decoding. A remote attacker could possibly use this issue to cause
curl to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-8622)

It was discovered that curl incorrectly handled shared cookies. A
remote server could possibly obtain incorrect cookies or other
sensitive information. (CVE-2016-8623)

Fernando Munoz discovered that curl incorrect parsed certain URLs. A
remote attacker could possibly use this issue to trick curl into
connecting to a different host. (CVE-2016-8624).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libcurl3, libcurl3-gnutls and / or libcurl3-nss
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libcurl3", pkgver:"7.22.0-3ubuntu4.17")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libcurl3-gnutls", pkgver:"7.22.0-3ubuntu4.17")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libcurl3-nss", pkgver:"7.22.0-3ubuntu4.17")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libcurl3", pkgver:"7.35.0-1ubuntu2.10")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libcurl3-gnutls", pkgver:"7.35.0-1ubuntu2.10")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libcurl3-nss", pkgver:"7.35.0-1ubuntu2.10")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libcurl3", pkgver:"7.47.0-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libcurl3-gnutls", pkgver:"7.47.0-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libcurl3-nss", pkgver:"7.47.0-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libcurl3", pkgver:"7.50.1-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libcurl3-gnutls", pkgver:"7.50.1-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libcurl3-nss", pkgver:"7.50.1-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcurl3 / libcurl3-gnutls / libcurl3-nss");
}
