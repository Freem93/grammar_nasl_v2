#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2808-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86848);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2015-5310", "CVE-2015-5314", "CVE-2015-5315", "CVE-2015-5316");
  script_osvdb_id(130094, 130096, 130113);
  script_xref(name:"USN", value:"2808-1");

  script_name(english:"Ubuntu 14.04 LTS / 15.04 / 15.10 : wpa vulnerabilities (USN-2808-1)");
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
"It was discovered that wpa_supplicant incorrectly handled WMM Sleep
Mode Response frame processing. A remote attacker could use this issue
to perform broadcast/multicast packet injections, or cause a denial of
service. (CVE-2015-5310)

It was discovered that wpa_supplicant and hostapd incorrectly handled
certain EAP-pwd messages. A remote attacker could use this issue to
cause a denial of service. (CVE-2015-5314, CVE-2015-5315)

It was discovered that wpa_supplicant incorrectly handled certain
EAP-pwd Confirm messages. A remote attacker could use this issue to
cause a denial of service. This issue only applied to Ubuntu 15.10.
(CVE-2015-5316).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hostapd and / or wpasupplicant packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hostapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wpasupplicant");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04|15\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 15.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"hostapd", pkgver:"2.1-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"wpasupplicant", pkgver:"2.1-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"hostapd", pkgver:"2.1-0ubuntu7.3")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"wpasupplicant", pkgver:"2.1-0ubuntu7.3")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"hostapd", pkgver:"2.4-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"wpasupplicant", pkgver:"2.4-0ubuntu3.2")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hostapd / wpasupplicant");
}
