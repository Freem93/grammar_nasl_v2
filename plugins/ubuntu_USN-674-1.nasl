#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-674-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37887);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-2940", "CVE-2008-2941");
  script_osvdb_id(47600);
  script_xref(name:"USN", value:"674-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS : hplip vulnerabilities (USN-674-1)");
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
"It was discovered that the hpssd tool of hplip did not validate
privileges in the alert-mailing function. A local attacker could
exploit this to gain privileges and send e-mail messages from the
account of the hplip user. This update alters hplip behaviour by
preventing users from setting alerts and by moving alert configuration
to a root-controlled /etc/hp/alerts.conf file. (CVE-2008-2940)

It was discovered that the hpssd tool of hplip did not correctly
handle certain commands. A local attacker could use a specially
crafted packet to crash hpssd, leading to a denial of service.
(CVE-2008-2941).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hpijs-ppds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip-ppds");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"hpijs", pkgver:"2.1.7+0.9.7-4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"hplip", pkgver:"0.9.7-4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"hplip-data", pkgver:"0.9.7-4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"hplip-ppds", pkgver:"0.9.7-4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"hpijs", pkgver:"2.7.7+2.7.7.dfsg.1-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"hpijs-ppds", pkgver:"2.7.7+2.7.7.dfsg.1-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"hplip", pkgver:"2.7.7.dfsg.1-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"hplip-data", pkgver:"2.7.7.dfsg.1-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"hplip-dbg", pkgver:"2.7.7.dfsg.1-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"hplip-doc", pkgver:"2.7.7.dfsg.1-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"hplip-gui", pkgver:"2.7.7.dfsg.1-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"hpijs", pkgver:"2.8.2+2.8.2-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"hpijs-ppds", pkgver:"2.8.2+2.8.2-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"hplip", pkgver:"2.8.2-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"hplip-data", pkgver:"2.8.2-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"hplip-dbg", pkgver:"2.8.2-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"hplip-doc", pkgver:"2.8.2-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"hplip-gui", pkgver:"2.8.2-0ubuntu8.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hpijs / hpijs-ppds / hplip / hplip-data / hplip-dbg / hplip-doc / etc");
}
