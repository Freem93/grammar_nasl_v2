#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1188-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55810);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/26 16:14:09 $");

  script_cve_id("CVE-2011-1831", "CVE-2011-1832", "CVE-2011-1833", "CVE-2011-1834", "CVE-2011-1835", "CVE-2011-1836", "CVE-2011-1837");
  script_xref(name:"USN", value:"1188-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 / 11.04 : ecryptfs-utils vulnerabilities (USN-1188-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vasiliy Kulikov and Dan Rosenberg discovered that eCryptfs incorrectly
validated permissions on the requested mountpoint. A local attacker
could use this flaw to mount to arbitrary locations, leading to
privilege escalation. (CVE-2011-1831)

Vasiliy Kulikov and Dan Rosenberg discovered that eCryptfs incorrectly
validated permissions on the requested mountpoint. A local attacker
could use this flaw to unmount to arbitrary locations, leading to a
denial of service. (CVE-2011-1832)

Vasiliy Kulikov and Dan Rosenberg discovered that eCryptfs incorrectly
validated permissions on the requested source directory. A local
attacker could use this flaw to mount an arbitrary directory, possibly
leading to information disclosure. A pending kernel update will
provide the other half of the fix for this issue. (CVE-2011-1833)

Dan Rosenberg and Marc Deslauriers discovered that eCryptfs
incorrectly handled modifications to the mtab file when an error
occurs. A local attacker could use this flaw to corrupt the mtab file,
and possibly unmount arbitrary locations, leading to a denial of
service. (CVE-2011-1834)

Marc Deslauriers discovered that eCryptfs incorrectly handled keys
when setting up an encrypted private directory. A local attacker could
use this flaw to manipulate keys during creation of a new user.
(CVE-2011-1835)

Marc Deslauriers discovered that eCryptfs incorrectly handled
permissions during recovery. A local attacker could use this flaw to
possibly access another user's data during the recovery process. This
issue only applied to Ubuntu 11.04. (CVE-2011-1836)

Vasiliy Kulikov discovered that eCryptfs incorrectly handled lock
counters. A local attacker could use this flaw to possibly overwrite
arbitrary files. The default symlink restrictions in Ubuntu 10.10 and
11.04 should protect against this issue. (CVE-2011-1837).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ecryptfs-utils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ecryptfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/10");
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

if (ubuntu_check(osver:"10.04", pkgname:"ecryptfs-utils", pkgver:"83-0ubuntu3.2.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"ecryptfs-utils", pkgver:"83-0ubuntu3.2.10.10.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"ecryptfs-utils", pkgver:"87-0ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ecryptfs-utils");
}
