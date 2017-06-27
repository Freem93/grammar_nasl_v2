#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-716-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38011);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-0780", "CVE-2008-0781", "CVE-2008-0782", "CVE-2008-1098", "CVE-2008-1099", "CVE-2009-0260", "CVE-2009-0312");
  script_bugtraq_id(28177, 33365, 33479);
  script_xref(name:"USN", value:"716-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : moin vulnerabilities (USN-716-1)");
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
"Fernando Quintero discovered than MoinMoin did not properly sanitize
its input when processing login requests, resulting in cross-site
scripting (XSS) vulnerabilities. With cross-site scripting
vulnerabilities, if a user were tricked into viewing server output
during a crafted server request, a remote attacker could exploit this
to modify the contents, or steal confidential data, within the same
domain. This issue affected Ubuntu 7.10 and 8.04 LTS. (CVE-2008-0780)

Fernando Quintero discovered that MoinMoin did not properly sanitize
its input when attaching files, resulting in cross-site scripting
vulnerabilities. This issue affected Ubuntu 6.06 LTS, 7.10 and 8.04
LTS. (CVE-2008-0781)

It was discovered that MoinMoin did not properly sanitize its input
when processing user forms. A remote attacker could submit crafted
cookie values and overwrite arbitrary files via directory traversal.
This issue affected Ubuntu 6.06 LTS, 7.10 and 8.04 LTS.
(CVE-2008-0782)

It was discovered that MoinMoin did not properly sanitize its input
when editing pages, resulting in cross-site scripting vulnerabilities.
This issue only affected Ubuntu 6.06 LTS and 7.10. (CVE-2008-1098)

It was discovered that MoinMoin did not properly enforce access
controls, which could allow a remoter attacker to view private pages.
This issue only affected Ubuntu 6.06 LTS and 7.10. (CVE-2008-1099)

It was discovered that MoinMoin did not properly sanitize its input
when attaching files and using the rename parameter, resulting in
cross-site scripting vulnerabilities. (CVE-2009-0260)

It was discovered that MoinMoin did not properly sanitize its input
when displaying error messages after processing spam, resulting in
cross-site scripting vulnerabilities. (CVE-2009-0312).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected moinmoin-common, python-moinmoin and / or
python2.4-moinmoin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:moinmoin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-moinmoin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-moinmoin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/29");
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
if (! ereg(pattern:"^(6\.06|7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"moinmoin-common", pkgver:"1.5.2-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python-moinmoin", pkgver:"1.5.2-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-moinmoin", pkgver:"1.5.2-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"moinmoin-common", pkgver:"1.5.7-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python-moinmoin", pkgver:"1.5.7-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"moinmoin-common", pkgver:"1.5.8-5.1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-moinmoin", pkgver:"1.5.8-5.1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-moinmoin", pkgver:"1.7.1-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "moinmoin-common / python-moinmoin / python2.4-moinmoin");
}
