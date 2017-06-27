#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-439-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28035);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:29:17 $");

  script_cve_id("CVE-2007-1536");
  script_bugtraq_id(23021);
  script_osvdb_id(34285);
  script_xref(name:"USN", value:"439-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS / 6.10 : file vulnerability (USN-439-1)");
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
"Jean-Sebastien Guay-Leroux discovered that 'file' did not correctly
check the size of allocated heap memory. If a user were tricked into
examining a specially crafted file with the 'file' utility, a remote
attacker could execute arbitrary code with user privileges.

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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagic-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-magic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-magic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/08");
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
if (! ereg(pattern:"^(5\.10|6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"file", pkgver:"4.12-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagic-dev", pkgver:"4.12-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagic1", pkgver:"4.12-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"file", pkgver:"4.16-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmagic-dev", pkgver:"4.16-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmagic1", pkgver:"4.16-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python-magic", pkgver:"4.16-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-magic", pkgver:"4.16-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"file", pkgver:"4.17-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmagic-dev", pkgver:"4.17-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmagic1", pkgver:"4.17-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python-magic", pkgver:"4.17-2ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file / libmagic-dev / libmagic1 / python-magic / python2.4-magic");
}
