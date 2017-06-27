#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-696-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36657);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/27 14:37:18 $");

  script_cve_id("CVE-2007-3372", "CVE-2008-5081");
  script_bugtraq_id(32825);
  script_osvdb_id(37507, 50929);
  script_xref(name:"USN", value:"696-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : avahi vulnerabilities (USN-696-1)");
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
"Emanuele Aina discovered that Avahi did not properly validate its
input when processing data over D-Bus. A local attacker could send an
empty TXT message via D-Bus and cause a denial of service (failed
assertion). This issue only affected Ubuntu 6.06 LTS. (CVE-2007-3372)

Hugo Dias discovered that Avahi did not properly verify its input when
processing mDNS packets. A remote attacker could send a crafted mDNS
packet and cause a denial of service (assertion failure).
(CVE-2008-5081).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-autoipd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-discover");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-dnsconfd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-ui-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-client-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-howl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-howl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-libdnssd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-libdnssd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-gobject-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-gobject0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt3-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt4-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-ui-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-ui0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:monodoc-avahi-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-avahi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"6.06", pkgname:"avahi-daemon", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avahi-discover", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avahi-dnsconfd", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avahi-utils", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-cil", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-client-dev", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-client3", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-common-data", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-common-dev", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-common3", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-compat-howl-dev", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-compat-howl0", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-compat-libdnssd-dev", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-compat-libdnssd1", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-core-dev", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-core4", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-glib-dev", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-glib1", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-qt3-1", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavahi-qt3-dev", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"monodoc-avahi-manual", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-avahi", pkgver:"0.6.10-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"avahi-autoipd", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"avahi-daemon", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"avahi-discover", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"avahi-dnsconfd", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"avahi-utils", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-client-dev", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-client3", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-common-data", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-common-dev", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-common3", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-compat-howl-dev", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-compat-howl0", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-compat-libdnssd-dev", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-compat-libdnssd1", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-core-dev", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-core5", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-glib-dev", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-glib1", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-qt3-1", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-qt3-dev", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-qt4-1", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-qt4-dev", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-ui-dev", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavahi-ui0", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python-avahi", pkgver:"0.6.20-2ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avahi-autoipd", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avahi-daemon", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avahi-dbg", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avahi-discover", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avahi-dnsconfd", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avahi-utils", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-client-dev", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-client3", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-common-data", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-common-dev", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-common3", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-compat-howl-dev", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-compat-howl0", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-compat-libdnssd-dev", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-compat-libdnssd1", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-core-dev", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-core5", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-glib-dev", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-glib1", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-gobject-dev", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-gobject0", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-qt3-1", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-qt3-dev", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-qt4-1", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-qt4-dev", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-ui-dev", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-ui0", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-avahi", pkgver:"0.6.22-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"avahi-autoipd", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"avahi-daemon", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"avahi-dbg", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"avahi-discover", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"avahi-dnsconfd", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"avahi-ui-utils", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"avahi-utils", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-client-dev", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-client3", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-common-data", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-common-dev", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-common3", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-compat-howl-dev", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-compat-howl0", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-compat-libdnssd-dev", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-compat-libdnssd1", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-core-dev", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-core5", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-glib-dev", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-glib1", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-gobject-dev", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-gobject0", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-qt3-1", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-qt3-dev", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-qt4-1", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-qt4-dev", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-ui-dev", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavahi-ui0", pkgver:"0.6.23-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-avahi", pkgver:"0.6.23-2ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi-autoipd / avahi-daemon / avahi-dbg / avahi-discover / etc");
}
