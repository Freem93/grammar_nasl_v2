#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2254-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76249);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/24 17:29:03 $");

  script_cve_id("CVE-2014-0185", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-4049");
  script_bugtraq_id(67118, 67759, 67765, 68007);
  script_osvdb_id(107559, 107560, 107994);
  script_xref(name:"USN", value:"2254-2");

  script_name(english:"Ubuntu 13.10 / 14.04 LTS : php5 updates (USN-2254-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2254-1 fixed vulnerabilities in PHP. The fix for CVE-2014-0185
further restricted the permissions on the PHP FastCGI Process Manager
(FPM) UNIX socket. This update grants socket access to the www-data
user and group so installations and documentation relying on the
previous socket permissions will continue to function.

Christian Hoffmann discovered that the PHP FastCGI Process Manager
(FPM) set incorrect permissions on the UNIX socket. A local attacker
could use this issue to possibly elevate their privileges. This issue
only affected Ubuntu 12.04 LTS, Ubuntu 13.10, and Ubuntu 14.04 LTS.
(CVE-2014-0185)

Francisco Alonso discovered that the PHP Fileinfo component
incorrectly handled certain CDF documents. A remote attacker
could use this issue to cause PHP to hang or crash,
resulting in a denial of service. (CVE-2014-0237,
CVE-2014-0238)

Stefan Esser discovered that PHP incorrectly handled DNS TXT
records. A remote attacker could use this issue to cause PHP
to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2014-4049).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php5-fpm package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(13\.10|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 13.10 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"13.10", pkgname:"php5-fpm", pkgver:"5.5.3+dfsg-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-fpm", pkgver:"5.5.9+dfsg-1ubuntu4.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php5-fpm");
}
