#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-403-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27991);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_cve_id("CVE-2006-6101", "CVE-2006-6102", "CVE-2006-6103");
  script_osvdb_id(32084);
  script_xref(name:"USN", value:"403-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS / 6.10 : xorg, xorg-server vulnerabilities (USN-403-1)");
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
"The DBE and Render extensions in X.org were vulnerable to integer
overflows, which could lead to memory overwrites. An authenticated
user could make a specially crafted request and execute arbitrary code
with root privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:x-window-system-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:x-window-system-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xbase-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-static-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-static-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-apm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-ark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-ati");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-chips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-cirrus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-cyrix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-dummy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-fbdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-glide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-glint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-i128");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-i740");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-i810");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-imstt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-mga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-neomagic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-newport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-nsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-nv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-rendition");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-s3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-s3virge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-savage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-siliconmotion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-sis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-sunbw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-suncg14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-suncg3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-suncg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-sunffb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-sunleo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-suntcx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-tdfx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-tga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-trident");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-tseng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-v4l");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-vesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-vga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-via");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-acecad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-aiptek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-calcomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-citron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-digitaledge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-dmc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-dynapro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-elographics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-fpit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-hyperpen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-kbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-magellan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-microtouch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-mouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-mutouch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-palmax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-penmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-spaceorb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-summa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-tek4957");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-void");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-wacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"5.10", pkgname:"x-window-system-core", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"x-window-system-dev", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xbase-clients", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xdmx", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xlibs", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xlibs-data", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xlibs-dev", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xlibs-static-dev", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xlibs-static-pic", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xnest", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xorg-common", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-common", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-core", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-dbg", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-apm", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-ark", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-ati", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-chips", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-cirrus", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-cyrix", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-dummy", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-fbdev", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-glide", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-glint", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-i128", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-i740", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-i810", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-imstt", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-mga", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-neomagic", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-newport", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-nsc", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-nv", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-rendition", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-s3", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-s3virge", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-savage", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-siliconmotion", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-sis", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-sunbw2", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-suncg14", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-suncg3", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-suncg6", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-sunffb", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-sunleo", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-suntcx", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-tdfx", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-tga", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-trident", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-tseng", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-v4l", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-vesa", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-vga", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-via", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-vmware", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-acecad", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-aiptek", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-calcomp", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-citron", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-digitaledge", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-dmc", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-dynapro", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-elographics", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-fpit", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-hyperpen", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-kbd", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-magellan", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-microtouch", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-mouse", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-mutouch", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-palmax", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-penmount", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-spaceorb", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-summa", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-tek4957", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-void", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-wacom", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xutils", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xvfb", pkgver:"6.8.2-77.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xdmx", pkgver:"1.0.2-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xdmx-tools", pkgver:"1.0.2-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xnest", pkgver:"1.0.2-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xserver-xorg-core", pkgver:"1:1.0.2-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xserver-xorg-dev", pkgver:"1.0.2-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xvfb", pkgver:"1.0.2-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xdmx", pkgver:"1.1.1-0ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xdmx-tools", pkgver:"1.1.1-0ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xnest", pkgver:"1.1.1-0ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xserver-xephyr", pkgver:"1.1.1-0ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xserver-xorg-core", pkgver:"1:1.1.1-0ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xserver-xorg-dev", pkgver:"1.1.1-0ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xvfb", pkgver:"1.1.1-0ubuntu12.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "x-window-system-core / x-window-system-dev / xbase-clients / xdmx / etc");
}
