#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1001-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49791);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2010-2526");
  script_bugtraq_id(42033);
  script_osvdb_id(66753);
  script_xref(name:"USN", value:"1001-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.04 / 9.10 / 10.04 LTS : lvm2 vulnerability (USN-1001-1)");
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
"The cluster logical volume manager daemon (clvmd) in LVM2 did not
correctly validate credentials. A local user could use this flaw to
manipulate logical volumes without root privileges and cause a denial
of service in the cluster.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dmeventd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dmsetup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdevmapper-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdevmapper-event1.02.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdevmapper1.02.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lvm2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/07");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"clvm", pkgver:"2.02.02-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"lvm2", pkgver:"2.02.02-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"clvm", pkgver:"2.02.26-1ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"lvm2", pkgver:"2.02.26-1ubuntu9.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"clvm", pkgver:"2.02.39-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"lvm2", pkgver:"2.02.39-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"clvm", pkgver:"2.02.39-0ubuntu11.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"lvm2", pkgver:"2.02.39-0ubuntu11.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"clvm", pkgver:"2.02.54-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dmeventd", pkgver:"1.02.39-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dmsetup", pkgver:"1.02.39-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libdevmapper-dev", pkgver:"1.02.39-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libdevmapper-event1.02.1", pkgver:"1.02.39-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libdevmapper1.02.1", pkgver:"1.02.39-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"lvm2", pkgver:"2.02.54-1ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clvm / dmeventd / dmsetup / libdevmapper-dev / etc");
}
