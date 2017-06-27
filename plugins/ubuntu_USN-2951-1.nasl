#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2951-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90589);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/01 21:07:48 $");

  script_cve_id("CVE-2015-7801", "CVE-2015-7802", "CVE-2016-2191", "CVE-2016-3981", "CVE-2016-3982");
  script_osvdb_id(128018, 128854, 136620, 136621, 137029);
  script_xref(name:"USN", value:"2951-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 : optipng vulnerabilities (USN-2951-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Gustavo Grieco discovered that OptiPNG incorrectly handled memory. A
remote attacker could use this issue with a specially crafted image
file to cause OptiPNG to crash, resulting in a denial of service.
(CVE-2015-7801)

Gustavo Grieco discovered that OptiPNG incorrectly handled memory. A
remote attacker could use this issue with a specially crafted image
file to cause OptiPNG to crash, resulting in a denial of service.
(CVE-2015-7802)

Hans Jerry Illikainen discovered that OptiPNG incorrectly handled
memory. A remote attacker could use this issue with a specially
crafted image file to cause OptiPNG to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2016-2191)

Henri Salo discovered that OptiPNG incorrectly handled memory. A
remote attacker could use this issue with a specially crafted image
file to cause OptiPNG to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2016-3981)

Henri Salo discovered that OptiPNG incorrectly handled memory. A
remote attacker could use this issue with a specially crafted image
file to cause OptiPNG to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2016-3982).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected optipng package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:U");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:optipng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/19");
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

if (ubuntu_check(osver:"12.04", pkgname:"optipng", pkgver:"0.6.4-1ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"optipng", pkgver:"0.6.4-1ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"optipng", pkgver:"0.7.5-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "optipng");
}
