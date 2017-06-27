#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-723-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36720);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-3546", "CVE-2008-5516", "CVE-2008-5517", "CVE-2008-5916");
  script_bugtraq_id(32967, 33355);
  script_osvdb_id(50918, 53538, 53539);
  script_xref(name:"USN", value:"723-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : git-core vulnerabilities (USN-723-1)");
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
"It was discovered that Git did not properly handle long file paths. If
a user were tricked into performing commands on a specially crafted
Git repository, an attacker could possibly execute arbitrary code with
the privileges of the user invoking the program. (CVE-2008-3546)

It was discovered that the Git web interface (gitweb) did not
correctly handle shell metacharacters when processing certain
commands. A remote attacker could send specially crafted commands to
the Git server and execute arbitrary code with the privileges of the
Git web server. This issue only applied to Ubuntu 7.10 and 8.04 LTS.
(CVE-2008-5516, CVE-2008-5517)

It was discovered that the Git web interface (gitweb) did not properly
restrict the diff.external configuration parameter. A local attacker
could exploit this issue and execute arbitrary code with the
privileges of the Git web server. This issue only applied to Ubuntu
8.04 LTS and 8.10. (CVE-2008-5916).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(78, 94, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-daemon-run");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/18");
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

if (ubuntu_check(osver:"6.06", pkgname:"git-arch", pkgver:"1.1.3-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"git-core", pkgver:"1.1.3-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"git-cvs", pkgver:"1.1.3-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"git-doc", pkgver:"1.1.3-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"git-email", pkgver:"1.1.3-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"git-svn", pkgver:"1.1.3-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gitk", pkgver:"1.1.3-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"git-arch", pkgver:"1.5.2.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"git-core", pkgver:"1:1.5.2.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"git-cvs", pkgver:"1.5.2.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"git-daemon-run", pkgver:"1.5.2.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"git-doc", pkgver:"1.5.2.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"git-email", pkgver:"1.5.2.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"git-gui", pkgver:"1.5.2.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"git-p4", pkgver:"1.5.2.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"git-svn", pkgver:"1.5.2.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gitk", pkgver:"1.5.2.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gitweb", pkgver:"1:1.5.2.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"git-arch", pkgver:"1.5.4.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"git-core", pkgver:"1:1.5.4.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"git-cvs", pkgver:"1.5.4.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"git-daemon-run", pkgver:"1.5.4.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"git-doc", pkgver:"1.5.4.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"git-email", pkgver:"1.5.4.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"git-gui", pkgver:"1.5.4.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"git-svn", pkgver:"1.5.4.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gitk", pkgver:"1.5.4.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gitweb", pkgver:"1:1.5.4.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"git-arch", pkgver:"1.5.6.3-1.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"git-core", pkgver:"1:1.5.6.3-1.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"git-cvs", pkgver:"1.5.6.3-1.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"git-daemon-run", pkgver:"1.5.6.3-1.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"git-doc", pkgver:"1.5.6.3-1.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"git-email", pkgver:"1.5.6.3-1.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"git-gui", pkgver:"1.5.6.3-1.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"git-svn", pkgver:"1.5.6.3-1.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gitk", pkgver:"1.5.6.3-1.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gitweb", pkgver:"1:1.5.6.3-1.1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git-arch / git-core / git-cvs / git-daemon-run / git-doc / etc");
}
