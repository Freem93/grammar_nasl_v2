#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-527-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28132);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_cve_id("CVE-2007-4993");
  script_osvdb_id(41340);
  script_xref(name:"USN", value:"527-1");

  script_name(english:"Ubuntu 7.04 : xen-3.0 vulnerability (USN-527-1)");
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
"Joris van Rantwijk discovered that the Xen host did not correctly
validate the contents of a Xen guests's grug.conf file. Xen guest root
users could exploit this to run arbitrary commands on the host when
the guest system was rebooted.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxen3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxen3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-xen3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-docs-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-3.0-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-3.0-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-3.0-i386-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-ioemu-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-utils-3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.04", pkgname:"libxen3.0", pkgver:"3.0.3-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxen3.0-dev", pkgver:"3.0.3-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python-xen3.0", pkgver:"3.0.3-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xen-docs-3.0", pkgver:"3.0.3-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xen-hypervisor-3.0-amd64", pkgver:"3.0.3-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xen-hypervisor-3.0-i386", pkgver:"3.0.3-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xen-hypervisor-3.0-i386-pae", pkgver:"3.0.3-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xen-ioemu-3.0", pkgver:"3.0.3-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xen-utils-3.0", pkgver:"3.0.3-0ubuntu10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxen3.0 / libxen3.0-dev / python-xen3.0 / xen-docs-3.0 / etc");
}
