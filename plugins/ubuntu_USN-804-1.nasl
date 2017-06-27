#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-804-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39851);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:37:19 $");

  script_cve_id("CVE-2009-1894");
  script_osvdb_id(56104);
  script_xref(name:"USN", value:"804-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : pulseaudio vulnerability (USN-804-1)");
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
"Tavis Ormandy, Julien Tinnes, and Yorick Koster discovered that
PulseAudio did not safely re-execute itself. A local attacker could
exploit this to gain root privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse-browse0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse-browse0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse-mainloop-glib0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse-mainloop-glib0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulsecore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulsecore5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulsecore9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulsecore9-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-esound-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-esound-compat-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-gconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-gconf-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-hal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-hal-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-lirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-lirc-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-x11-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-zeroconf-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-utils-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/17");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libpulse-browse0", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpulse-browse0-dbg", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpulse-dev", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpulse-mainloop-glib0", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpulse-mainloop-glib0-dbg", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpulse0", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpulse0-dbg", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpulsecore5", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpulsecore5-dbg", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-dbg", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-esound-compat", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-esound-compat-dbg", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-module-gconf", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-module-gconf-dbg", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-module-hal", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-module-hal-dbg", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-module-lirc", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-module-lirc-dbg", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-module-x11", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-module-x11-dbg", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-module-zeroconf", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-module-zeroconf-dbg", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-utils", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pulseaudio-utils-dbg", pkgver:"0.9.10-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpulse-browse0", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpulse-browse0-dbg", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpulse-dev", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpulse-mainloop-glib0", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpulse-mainloop-glib0-dbg", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpulse0", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpulse0-dbg", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpulsecore5", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpulsecore5-dbg", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-dbg", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-esound-compat", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-esound-compat-dbg", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-module-gconf", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-module-gconf-dbg", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-module-hal", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-module-hal-dbg", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-module-lirc", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-module-lirc-dbg", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-module-x11", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-module-x11-dbg", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-module-zeroconf", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-module-zeroconf-dbg", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-utils", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pulseaudio-utils-dbg", pkgver:"0.9.10-2ubuntu9.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpulse-browse0", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpulse-browse0-dbg", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpulse-dev", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpulse-mainloop-glib0", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpulse-mainloop-glib0-dbg", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpulse0", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpulse0-dbg", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpulsecore9", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpulsecore9-dbg", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio", pkgver:"1:0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-dbg", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-esound-compat", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-esound-compat-dbg", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-module-gconf", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-module-gconf-dbg", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-module-hal", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-module-hal-dbg", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-module-lirc", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-module-lirc-dbg", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-module-x11", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-module-x11-dbg", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-module-zeroconf", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-module-zeroconf-dbg", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-utils", pkgver:"0.9.14-0ubuntu20.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pulseaudio-utils-dbg", pkgver:"0.9.14-0ubuntu20.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpulse-browse0 / libpulse-browse0-dbg / libpulse-dev / etc");
}
