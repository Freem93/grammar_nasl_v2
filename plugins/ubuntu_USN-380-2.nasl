#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-380-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27963);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_bugtraq_id(21016);
  script_xref(name:"USN", value:"380-2");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS / 6.10 : avahi regression (USN-380-2)");
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
"USN-380-1 fixed a vulnerability in Avahi. However, if used with
Network manager, that version occasionally failed to resolve .local
DNS names until Avahi got restarted. This update fixes the problem.

We apologize for the inconvenience.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-discover");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-dnsconfd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-client-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-client1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-howl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-howl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-libdnssd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-libdnssd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-glib0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt3-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt4-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt4-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:monodoc-avahi-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-avahi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.10|6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"avahi-daemon", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"avahi-dnsconfd", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"avahi-utils", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavahi-cil", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavahi-client-dev", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavahi-client1", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavahi-common-dev", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavahi-common0", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavahi-core-dev", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavahi-core1", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavahi-glib-dev", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavahi-glib0", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavahi-qt3-0", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavahi-qt3-dev", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavahi-qt4-0", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavahi-qt4-dev", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4-avahi", pkgver:"0.5.2-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avahi-daemon", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avahi-discover", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avahi-dnsconfd", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avahi-utils", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-cil", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-client-dev", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-client3", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-common-data", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-common-dev", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-common3", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-compat-howl-dev", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-compat-howl0", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-compat-libdnssd-dev", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-compat-libdnssd1", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-core-dev", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-core4", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-glib-dev", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-glib1", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-qt3-1", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-qt3-dev", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"monodoc-avahi-manual", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-avahi", pkgver:"0.6.10-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"avahi-daemon", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"avahi-discover", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"avahi-dnsconfd", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"avahi-utils", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-client-dev", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-client3", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-common-data", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-common-dev", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-common3", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-compat-howl-dev", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-compat-howl0", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-compat-libdnssd-dev", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-compat-libdnssd1", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-core-dev", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-core4", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-glib-dev", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-glib1", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-qt3-1", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-qt3-dev", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-qt4-1", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libavahi-qt4-dev", pkgver:"0.6.13-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python-avahi", pkgver:"0.6.13-2ubuntu2.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi-daemon / avahi-discover / avahi-dnsconfd / avahi-utils / etc");
}
