#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-810-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65117);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2409");
  script_xref(name:"USN", value:"810-3");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : nss regression (USN-810-3)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-810-1 fixed vulnerabilities in NSS. Jozsef Kadlecsik noticed that
the new libraries on amd64 did not correctly set stack memory flags,
and caused applications using NSS (e.g. Firefox) to have an executable
stack. This reduced the effectiveness of some defensive security
protections. This update fixes the problem.

We apologize for the inconvenience.

Moxie Marlinspike discovered that NSS did not properly handle regular
expressions in certificate names. A remote attacker could create a
specially crafted certificate to cause a denial of service (via
application crash) or execute arbitrary code as the user invoking the
program. (CVE-2009-2404)

Moxie Marlinspike and Dan Kaminsky independently discovered
that NSS did not properly handle certificates with NULL
characters in the certificate name. An attacker could
exploit this to perform a man in the middle attack to view
sensitive information or alter encrypted communications.
(CVE-2009-2408)

Dan Kaminsky discovered NSS would still accept certificates
with MD2 hash signatures. As a result, an attacker could
potentially create a malicious trusted certificate to
impersonate another site. (CVE-2009-2409).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libnss3-1d package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3-1d");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"8.04", pkgname:"libnss3-1d", pkgver:"3.12.3.1-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libnss3-1d", pkgver:"3.12.3.1-0ubuntu0.8.10.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libnss3-1d", pkgver:"3.12.3.1-0ubuntu0.9.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnss3-1d");
}
