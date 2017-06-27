#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1032-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51136);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2010-4344");
  script_bugtraq_id(45308);
  script_osvdb_id(69685);
  script_xref(name:"USN", value:"1032-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.10 : exim4 vulnerability (USN-1032-1)");
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
"Sergey Kononenko and Eugene Bujak discovered that Exim did not
correctly truncate string expansions. A remote attacker could send
specially crafted email traffic to run arbitrary code as the Exim
user, which could also lead to root privileges.

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
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim4 string_format Function Heap Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/12");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"exim4", pkgver:"4.60-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-base", pkgver:"4.60-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-config", pkgver:"4.60-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-daemon-custom", pkgver:"4.60-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-daemon-heavy", pkgver:"4.60-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-daemon-light", pkgver:"4.60-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"eximon4", pkgver:"4.60-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4", pkgver:"4.69-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-base", pkgver:"4.69-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-config", pkgver:"4.69-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-daemon-custom", pkgver:"4.69-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-daemon-heavy", pkgver:"4.69-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-daemon-heavy-dbg", pkgver:"4.69-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-daemon-light", pkgver:"4.69-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-daemon-light-dbg", pkgver:"4.69-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-dbg", pkgver:"4.69-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exim4-dev", pkgver:"4.69-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"eximon4", pkgver:"4.69-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4", pkgver:"4.69-11ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-base", pkgver:"4.69-11ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-config", pkgver:"4.69-11ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-daemon-custom", pkgver:"4.69-11ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-daemon-heavy", pkgver:"4.69-11ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-daemon-heavy-dbg", pkgver:"4.69-11ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-daemon-light", pkgver:"4.69-11ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-daemon-light-dbg", pkgver:"4.69-11ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-dbg", pkgver:"4.69-11ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"exim4-dev", pkgver:"4.69-11ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"eximon4", pkgver:"4.69-11ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim4 / exim4-base / exim4-config / exim4-daemon-custom / etc");
}
