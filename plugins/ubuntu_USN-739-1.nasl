#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-739-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37607);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-0135", "CVE-2009-0136");
  script_bugtraq_id(33210);
  script_osvdb_id(53459);
  script_xref(name:"USN", value:"739-1");

  script_name(english:"Ubuntu 7.10 / 8.04 LTS / 8.10 : amarok vulnerabilities (USN-739-1)");
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
"It was discovered that Amarok did not correctly handle certain
malformed tags in Audible Audio (.aa) files. If a user were tricked
into opening a crafted Audible Audio file, an attacker could execute
arbitrary code with the privileges of the user invoking the program.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:amarok");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:amarok-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:amarok-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:amarok-engine-xine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:amarok-engine-yauap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:amarok-engines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:amarok-xine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! ereg(pattern:"^(7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.10", pkgname:"amarok", pkgver:"2:1.4.7-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"amarok-engines", pkgver:"1.4.7-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"amarok-xine", pkgver:"1.4.7-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"amarok", pkgver:"2:1.4.9.1-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"amarok-engines", pkgver:"1.4.9.1-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"amarok-xine", pkgver:"1.4.9.1-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"amarok", pkgver:"2:1.4.10-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"amarok-common", pkgver:"1.4.10-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"amarok-dbg", pkgver:"1.4.10-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"amarok-engine-xine", pkgver:"1.4.10-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"amarok-engine-yauap", pkgver:"1.4.10-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"amarok-engines", pkgver:"1.4.10-0ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "amarok / amarok-common / amarok-dbg / amarok-engine-xine / etc");
}
