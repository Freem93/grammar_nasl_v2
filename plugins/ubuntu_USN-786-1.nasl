#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-786-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39363);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
  script_bugtraq_id(35221, 35251, 35253);
  script_osvdb_id(55057, 55059);
  script_xref(name:"USN", value:"786-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : apr-util vulnerabilities (USN-786-1)");
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
"Matthew Palmer discovered an underflow flaw in apr-util. An attacker
could cause a denial of service via application crash in Apache using
a crafted SVNMasterURI directive, .htaccess file, or when using
mod_apreq2. Applications using libapreq2 are also affected.
(CVE-2009-0023)

It was discovered that the XML parser did not properly handle entity
expansion. A remote attacker could cause a denial of service via
memory resource consumption by sending a crafted request to an Apache
server configured to use mod_dav or mod_dav_svn. (CVE-2009-1955)

C. Michael Pilato discovered an off-by-one buffer overflow in apr-util
when formatting certain strings. For big-endian machines (powerpc,
hppa and sparc in Ubuntu), a remote attacker could cause a denial of
service or information disclosure leak. All other architectures for
Ubuntu are not considered to be at risk. (CVE-2009-1956).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libaprutil1, libaprutil1-dbg and / or
libaprutil1-dev packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libaprutil1", pkgver:"1.2.12+dfsg-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libaprutil1-dbg", pkgver:"1.2.12+dfsg-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libaprutil1-dev", pkgver:"1.2.12+dfsg-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libaprutil1", pkgver:"1.2.12+dfsg-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libaprutil1-dbg", pkgver:"1.2.12+dfsg-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libaprutil1-dev", pkgver:"1.2.12+dfsg-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libaprutil1", pkgver:"1.2.12+dfsg-8ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libaprutil1-dbg", pkgver:"1.2.12+dfsg-8ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libaprutil1-dev", pkgver:"1.2.12+dfsg-8ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libaprutil1 / libaprutil1-dbg / libaprutil1-dev");
}
