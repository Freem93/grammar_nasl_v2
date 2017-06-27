#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1140-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55102);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/27 14:13:24 $");

  script_cve_id("CVE-2009-0887", "CVE-2010-3316", "CVE-2010-3430", "CVE-2010-3431", "CVE-2010-3435", "CVE-2010-3853", "CVE-2010-4706", "CVE-2010-4707");
  script_bugtraq_id(34010, 42472, 43487, 44590, 46045);
  script_osvdb_id(53112, 68991, 68992, 68993, 68994, 70652, 70653);
  script_xref(name:"USN", value:"1140-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 : pam vulnerabilities (USN-1140-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Marcus Granado discovered that PAM incorrectly handled configuration
files with non-ASCII usernames. A remote attacker could use this flaw
to cause a denial of service, or possibly obtain login access with a
different users username. This issue only affected Ubuntu 8.04 LTS.
(CVE-2009-0887)

It was discovered that the PAM pam_xauth, pam_env and pam_mail modules
incorrectly handled dropping privileges when performing operations. A
local attacker could use this flaw to read certain arbitrary files,
and access other sensitive information. (CVE-2010-3316, CVE-2010-3430,
CVE-2010-3431, CVE-2010-3435)

It was discovered that the PAM pam_namespace module incorrectly
cleaned the environment during execution of the namespace.init script.
A local attacker could use this flaw to possibly gain privileges.
(CVE-2010-3853)

It was discovered that the PAM pam_xauth module incorrectly handled
certain failures. A local attacker could use this flaw to delete
certain unintended files. (CVE-2010-4706)

It was discovered that the PAM pam_xauth module incorrectly verified
certain file properties. A local attacker could use this flaw to cause
a denial of service. (CVE-2010-4707).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpam-modules package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/13");
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
if (! ereg(pattern:"^(8\.04|10\.04|10\.10|11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libpam-modules", pkgver:"0.99.7.1-5ubuntu6.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpam-modules", pkgver:"1.1.1-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libpam-modules", pkgver:"1.1.1-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libpam-modules", pkgver:"1.1.2-2ubuntu8.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpam-modules");
}
