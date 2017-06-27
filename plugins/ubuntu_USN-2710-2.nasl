#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2710-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85533);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/24 17:44:50 $");

  script_cve_id("CVE-2015-5352", "CVE-2015-5600");
  script_xref(name:"USN", value:"2710-2");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 : openssh regression (USN-2710-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2710-1 fixed vulnerabilities in OpenSSH. The upstream fix for
CVE-2015-5600 caused a regression resulting in random authentication
failures in non-default configurations. This update fixes the problem.

Moritz Jodeit discovered that OpenSSH incorrectly handled usernames
when using PAM authentication. If an additional vulnerability were
discovered in the OpenSSH unprivileged child process, this issue could
allow a remote attacker to perform user impersonation. (CVE number
pending)

Moritz Jodeit discovered that OpenSSH incorrectly handled
context memory when using PAM authentication. If an
additional vulnerability were discovered in the OpenSSH
unprivileged child process, this issue could allow a remote
attacker to bypass authentication or possibly execute
arbitrary code. (CVE number pending)

Jann Horn discovered that OpenSSH incorrectly handled time
windows for X connections. A remote attacker could use this
issue to bypass certain access restrictions. (CVE-2015-5352)

It was discovered that OpenSSH incorrectly handled
keyboard-interactive authentication. In a non-default
configuration, a remote attacker could possibly use this
issue to perform a brute-force password attack.
(CVE-2015-5600).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh-server package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"openssh-server", pkgver:"1:5.9p1-5ubuntu1.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openssh-server", pkgver:"1:6.6p1-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"openssh-server", pkgver:"1:6.7p1-5ubuntu1.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh-server");
}
