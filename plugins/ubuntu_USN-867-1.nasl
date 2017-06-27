#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-867-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43087);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/27 14:45:43 $");

  script_cve_id("CVE-2009-3563");
  script_bugtraq_id(37255);
  script_osvdb_id(60847);
  script_xref(name:"USN", value:"867-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 / 9.10 : ntp vulnerability (USN-867-1)");
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
"Robin Park and Dmitri Vinokurov discovered a logic error in ntpd. A
remote attacker could send a crafted NTP mode 7 packet with a spoofed
IP address of an affected server and cause a denial of service via CPU
and disk resource consumption.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntp-refclock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntp-simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/09");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"ntp", pkgver:"1:4.2.0a+stable-8.1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ntp-doc", pkgver:"4.2.0a+stable-8.1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ntp-refclock", pkgver:"4.2.0a+stable-8.1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ntp-server", pkgver:"1:4.2.0a+stable-8.1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ntp-simple", pkgver:"4.2.0a+stable-8.1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ntpdate", pkgver:"4.2.0a+stable-8.1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ntp", pkgver:"1:4.2.4p4+dfsg-3ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ntp-doc", pkgver:"4.2.4p4+dfsg-3ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ntpdate", pkgver:"4.2.4p4+dfsg-3ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ntp", pkgver:"1:4.2.4p4+dfsg-6ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ntp-doc", pkgver:"4.2.4p4+dfsg-6ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ntpdate", pkgver:"4.2.4p4+dfsg-6ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ntp", pkgver:"1:4.2.4p4+dfsg-7ubuntu5.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ntp-doc", pkgver:"4.2.4p4+dfsg-7ubuntu5.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ntpdate", pkgver:"4.2.4p4+dfsg-7ubuntu5.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ntp", pkgver:"1:4.2.4p6+dfsg-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ntp-doc", pkgver:"4.2.4p6+dfsg-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ntpdate", pkgver:"4.2.4p6+dfsg-1ubuntu5.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-doc / ntp-refclock / ntp-server / ntp-simple / ntpdate");
}
