#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1152-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55167);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/26 16:14:08 $");

  script_cve_id("CVE-2010-2238", "CVE-2011-1486", "CVE-2011-2178");
  script_bugtraq_id(47148);
  script_osvdb_id(72643, 74559);
  script_xref(name:"USN", value:"1152-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 / 11.04 : libvirt vulnerabilities (USN-1152-1)");
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
"It was discovered that libvirt did not use thread-safe error
reporting. A remote attacker could exploit this to cause a denial of
service via application crash. (CVE-2011-1486)

Eric Blake discovered that libvirt had an off-by-one error which could
be used to reopen disk probing and bypass the fix for CVE-2010-2238. A
privileged attacker in the guest could exploit this to read arbitrary
files on the host. This issue only affected Ubuntu 11.04. By default,
guests are confined by an AppArmor profile which provided partial
protection against this flaw. (CVE-2011-2178).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt-bin and / or libvirt0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/17");
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
if (! ereg(pattern:"^(10\.04|10\.10|11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10 / 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libvirt-bin", pkgver:"0.7.5-5ubuntu27.13")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libvirt0", pkgver:"0.7.5-5ubuntu27.13")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libvirt-bin", pkgver:"0.8.3-1ubuntu18")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libvirt0", pkgver:"0.8.3-1ubuntu18")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libvirt-bin", pkgver:"0.8.8-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libvirt0", pkgver:"0.8.8-1ubuntu6.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt-bin / libvirt0");
}
