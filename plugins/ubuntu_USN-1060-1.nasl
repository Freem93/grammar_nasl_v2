#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1060-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51954);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2010-2023", "CVE-2010-2024", "CVE-2010-4345", "CVE-2011-0017");
  script_bugtraq_id(40451, 40454, 45341, 46065);
  script_osvdb_id(65158, 65159, 69860, 70696);
  script_xref(name:"USN", value:"1060-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : exim4 vulnerabilities (USN-1060-1)");
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
"It was discovered that Exim contained a design flaw in the way it
processed alternate configuration files. An attacker that obtained
privileges of the 'Debian-exim' user could use an alternate
configuration file to obtain root privileges. (CVE-2010-4345)

It was discovered that Exim incorrectly handled certain return values
when handling logging. An attacker that obtained privileges of the
'Debian-exim' user could use this flaw to obtain root privileges.
(CVE-2011-0017)

Dan Rosenberg discovered that Exim incorrectly handled writable
sticky-bit mail directories. If Exim were configured in this manner, a
local user could use this flaw to cause a denial of service or
possibly gain privileges. This issue only applied to Ubuntu 6.06 LTS,
8.04 LTS, 9.10, and 10.04 LTS. (CVE-2010-2023)

Dan Rosenberg discovered that Exim incorrectly handled MBX locking. If
Exim were configured in this manner, a local user could use this flaw
to cause a denial of service or possibly gain privileges. This issue
only applied to Ubuntu 6.06 LTS, 8.04 LTS, 9.10, and 10.04 LTS.
(CVE-2010-2024).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim4 string_format Function Heap Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-heavy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-heavy-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-light");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-light-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eximon4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"exim4", pkgver:"4.60-3ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-base", pkgver:"4.60-3ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-config", pkgver:"4.60-3ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-daemon-custom", pkgver:"4.60-3ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-daemon-heavy", pkgver:"4.60-3ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-daemon-light", pkgver:"4.60-3ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"eximon4", pkgver:"4.60-3ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4", pkgver:"4.69-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-base", pkgver:"4.69-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-config", pkgver:"4.69-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-daemon-custom", pkgver:"4.69-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-daemon-heavy", pkgver:"4.69-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-daemon-heavy-dbg", pkgver:"4.69-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-daemon-light", pkgver:"4.69-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-daemon-light-dbg", pkgver:"4.69-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-dbg", pkgver:"4.69-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-dev", pkgver:"4.69-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"eximon4", pkgver:"4.69-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4", pkgver:"4.69-11ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-base", pkgver:"4.69-11ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-config", pkgver:"4.69-11ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-daemon-custom", pkgver:"4.69-11ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-daemon-heavy", pkgver:"4.69-11ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-daemon-heavy-dbg", pkgver:"4.69-11ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-daemon-light", pkgver:"4.69-11ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-daemon-light-dbg", pkgver:"4.69-11ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-dbg", pkgver:"4.69-11ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-dev", pkgver:"4.69-11ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"eximon4", pkgver:"4.69-11ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"exim4", pkgver:"4.71-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"exim4-base", pkgver:"4.71-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"exim4-config", pkgver:"4.71-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"exim4-daemon-custom", pkgver:"4.71-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"exim4-daemon-heavy", pkgver:"4.71-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"exim4-daemon-heavy-dbg", pkgver:"4.71-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"exim4-daemon-light", pkgver:"4.71-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"exim4-daemon-light-dbg", pkgver:"4.71-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"exim4-dbg", pkgver:"4.71-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"exim4-dev", pkgver:"4.71-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"eximon4", pkgver:"4.71-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"exim4", pkgver:"4.72-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"exim4-base", pkgver:"4.72-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"exim4-config", pkgver:"4.72-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"exim4-daemon-custom", pkgver:"4.72-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"exim4-daemon-heavy", pkgver:"4.72-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"exim4-daemon-heavy-dbg", pkgver:"4.72-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"exim4-daemon-light", pkgver:"4.72-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"exim4-daemon-light-dbg", pkgver:"4.72-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"exim4-dbg", pkgver:"4.72-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"exim4-dev", pkgver:"4.72-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"eximon4", pkgver:"4.72-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim4 / exim4-base / exim4-config / exim4-daemon-custom / etc");
}
