#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2352-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77809);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/06/03 14:00:06 $");

  script_cve_id("CVE-2014-3635", "CVE-2014-3636", "CVE-2014-3637", "CVE-2014-3638", "CVE-2014-3639");
  script_bugtraq_id(69829, 69831, 69832, 69833, 69834);
  script_osvdb_id(111638, 111639, 111640, 111641, 111642);
  script_xref(name:"USN", value:"2352-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 14.04 LTS : dbus vulnerabilities (USN-2352-1)");
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
"Simon McVittie discovered that DBus incorrectly handled the file
descriptors message limit. A local attacker could use this issue to
cause DBus to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only applied to Ubuntu 12.04 LTS
and Ubuntu 14.04 LTS. (CVE-2014-3635)

Alban Crequy discovered that DBus incorrectly handled a large number
of file descriptor messages. A local attacker could use this issue to
cause DBus to stop responding, resulting in a denial of service. This
issue only applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2014-3636)

Alban Crequy discovered that DBus incorrectly handled certain file
descriptor messages. A local attacker could use this issue to cause
DBus to maintain persistent connections, possibly resulting in a
denial of service. This issue only applied to Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2014-3637)

Alban Crequy discovered that DBus incorrectly handled a large number
of parallel connections and parallel message calls. A local attacker
could use this issue to cause DBus to consume resources, possibly
resulting in a denial of service. (CVE-2014-3638)

Alban Crequy discovered that DBus incorrectly handled incomplete
connections. A local attacker could use this issue to cause DBus to
fail legitimate connection attempts, resulting in a denial of service.
(CVE-2014-3639).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dbus and / or libdbus-1-3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-1-3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/23");
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
if (! ereg(pattern:"^(10\.04|12\.04|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"dbus", pkgver:"1.2.16-2ubuntu4.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libdbus-1-3", pkgver:"1.2.16-2ubuntu4.8")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"dbus", pkgver:"1.4.18-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libdbus-1-3", pkgver:"1.4.18-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"dbus", pkgver:"1.6.18-0ubuntu4.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libdbus-1-3", pkgver:"1.6.18-0ubuntu4.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus / libdbus-1-3");
}
