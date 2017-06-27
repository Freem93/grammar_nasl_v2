#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1965-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70087);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/25 16:27:07 $");

  script_cve_id("CVE-2013-4314");
  script_bugtraq_id(62258);
  script_osvdb_id(97013);
  script_xref(name:"USN", value:"1965-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 12.10 / 13.04 : pyopenssl vulnerability (USN-1965-1)");
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
"It was discovered that pyOpenSSL did not properly handle certificates
with NULL characters in the Subject Alternative Name field. An
attacker could exploit this to perform a man in the middle attack to
view sensitive information or alter encrypted communications.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-openssl and / or python3-openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|12\.04|12\.10|13\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 12.10 / 13.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"python-openssl", pkgver:"0.10-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python-openssl", pkgver:"0.12-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"python-openssl", pkgver:"0.13-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"python3-openssl", pkgver:"0.13-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"python-openssl", pkgver:"0.13-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"python3-openssl", pkgver:"0.13-2ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-openssl / python3-openssl");
}
