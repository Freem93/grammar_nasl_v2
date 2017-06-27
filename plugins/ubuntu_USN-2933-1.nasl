#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2933-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89962);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/01 20:56:53 $");

  script_cve_id("CVE-2014-2972", "CVE-2016-1531");
  script_osvdb_id(109455, 135280);
  script_xref(name:"USN", value:"2933-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 : exim4 vulnerabilities (USN-2933-1)");
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
"It was discovered that Exim incorrectly filtered environment variables
when used with the perl_startup configuration option. If the
perl_startup option was enabled, a local attacker could use this issue
to escalate their privileges to the root user. This issue has been
fixed by having Exim clean the complete execution environment by
default on startup, including any subprocesses such as transports that
call other programs. This change in behaviour may break existing
installations and can be adjusted by using two new configuration
options, keep_environment and add_environment. (CVE-2016-1531)

Patrick William discovered that Exim incorrectly expanded mathematical
comparisons twice. A local attacker could possibly use this issue to
perform arbitrary file operations as the Exim user. This issue only
affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-2972).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected exim4-daemon-custom, exim4-daemon-heavy and / or
exim4-daemon-light packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-heavy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-light");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/16");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"exim4-daemon-custom", pkgver:"4.76-3ubuntu3.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"exim4-daemon-heavy", pkgver:"4.76-3ubuntu3.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"exim4-daemon-light", pkgver:"4.76-3ubuntu3.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"exim4-daemon-custom", pkgver:"4.82-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"exim4-daemon-heavy", pkgver:"4.82-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"exim4-daemon-light", pkgver:"4.82-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"exim4-daemon-heavy", pkgver:"4.86-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"exim4-daemon-light", pkgver:"4.86-3ubuntu1.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim4-daemon-custom / exim4-daemon-heavy / exim4-daemon-light");
}
