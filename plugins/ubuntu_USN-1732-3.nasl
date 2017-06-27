#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1732-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65684);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/25 16:27:05 $");

  script_cve_id("CVE-2012-2686", "CVE-2013-0169");
  script_bugtraq_id(57778);
  script_xref(name:"USN", value:"1732-3");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 : openssl vulnerability (USN-1732-3)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-1732-1 fixed vulnerabilities in OpenSSL. The fix for CVE-2013-0169
and CVE-2012-2686 was reverted in USN-1732-2 because of a regression.
This update restores the security fix, and includes an extra fix from
upstream to address the AES-NI regression. We apologize for the
inconvenience.

Adam Langley and Wolfgang Ettlingers discovered that OpenSSL
incorrectly handled certain crafted CBC data when used with AES-NI. A
remote attacker could use this issue to cause OpenSSL to crash,
resulting in a denial of service. This issue only affected Ubuntu
12.04 LTS and Ubuntu 12.10. (CVE-2012-2686)

Nadhem Alfardan and Kenny Paterson discovered that the TLS
protocol as used in OpenSSL was vulnerable to a timing
side-channel attack known as the 'Lucky Thirteen' issue. A
remote attacker could use this issue to perform
plaintext-recovery attacks via analysis of timing data.
(CVE-2013-0169).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libssl1.0.0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/26");
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
if (! ereg(pattern:"^(12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libssl1.0.0", pkgver:"1.0.1-4ubuntu5.8")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libssl1.0.0", pkgver:"1.0.1c-3ubuntu2.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssl1.0.0");
}
