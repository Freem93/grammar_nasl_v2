#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-813-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40531);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:37:19 $");

  script_cve_id("CVE-2009-2412");
  script_bugtraq_id(35949);
  script_osvdb_id(56765, 56766);
  script_xref(name:"USN", value:"813-3");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : apr-util vulnerability (USN-813-3)");
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
"USN-813-1 fixed vulnerabilities in apr. This update provides the
corresponding updates for apr-util.

Matt Lewis discovered that apr did not properly sanitize its input
when allocating memory. If an application using apr processed crafted
input, a remote attacker could cause a denial of service or
potentially execute arbitrary code as the user invoking the
application.

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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/10");
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

if (ubuntu_check(osver:"8.04", pkgname:"libaprutil1", pkgver:"1.2.12+dfsg-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libaprutil1-dbg", pkgver:"1.2.12+dfsg-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libaprutil1-dev", pkgver:"1.2.12+dfsg-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libaprutil1", pkgver:"1.2.12+dfsg-7ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libaprutil1-dbg", pkgver:"1.2.12+dfsg-7ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libaprutil1-dev", pkgver:"1.2.12+dfsg-7ubuntu0.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libaprutil1", pkgver:"1.2.12+dfsg-8ubuntu0.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libaprutil1-dbg", pkgver:"1.2.12+dfsg-8ubuntu0.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libaprutil1-dev", pkgver:"1.2.12+dfsg-8ubuntu0.3")) flag++;

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
