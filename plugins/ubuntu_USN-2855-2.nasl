#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2855-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88804);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2015-3223", "CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299", "CVE-2015-5330", "CVE-2015-7540", "CVE-2015-8467");
  script_osvdb_id(131934, 131935, 131936, 131937, 131938, 131939, 131940);
  script_xref(name:"USN", value:"2855-2");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 : samba regression (USN-2855-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2855-1 fixed vulnerabilities in Samba. The upstream fix for
CVE-2015-5252 introduced a regression in certain specific
environments. This update fixes the problem.

Thilo Uttendorfer discovered that the Samba LDAP server incorrectly
handled certain packets. A remote attacker could use this issue to
cause the LDAP server to stop responding, resulting in a denial of
service. This issue only affected Ubuntu 14.04 LTS, Ubuntu 15.04 and
Ubuntu 15.10. (CVE-2015-3223)

Jan Kasprzak discovered that Samba incorrectly handled
certain symlinks. A remote attacker could use this issue to
access files outside the exported share path.
(CVE-2015-5252)

Stefan Metzmacher discovered that Samba did not enforce
signing when creating encrypted connections. If a remote
attacker were able to perform a man-in-the-middle attack,
this flaw could be exploited to view sensitive information.
(CVE-2015-5296)

It was discovered that Samba incorrectly performed access
control when using the VFS shadow_copy2 module. A remote
attacker could use this issue to access snapshots, contrary
to intended permissions. (CVE-2015-5299)

Douglas Bagnall discovered that Samba incorrectly handled
certain string lengths. A remote attacker could use this
issue to possibly access sensitive information.
(CVE-2015-5330)

It was discovered that the Samba LDAP server incorrectly
handled certain packets. A remote attacker could use this
issue to cause the LDAP server to stop responding, resulting
in a denial of service. This issue only affected Ubuntu
14.04 LTS, Ubuntu 15.04 and Ubuntu 15.10. (CVE-2015-7540)

Andrew Bartlett discovered that Samba incorrectly checked
administrative privileges during creation of machine
accounts. A remote attacker could possibly use this issue to
bypass intended access restrictions in certain environments.
This issue only affected Ubuntu 14.04 LTS, Ubuntu 15.04 and
Ubuntu 15.10. (CVE-2015-8467).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected samba package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
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

if (ubuntu_check(osver:"12.04", pkgname:"samba", pkgver:"2:3.6.3-2ubuntu2.14")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"samba", pkgver:"2:4.1.6+dfsg-1ubuntu2.14.04.12")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"samba", pkgver:"2:4.1.17+dfsg-4ubuntu3.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
