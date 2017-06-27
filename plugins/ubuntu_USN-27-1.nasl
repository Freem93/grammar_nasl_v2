#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-27-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20642);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/25 16:34:55 $");

  script_cve_id("CVE-2004-0687", "CVE-2004-0688");
  script_xref(name:"USN", value:"27-1");

  script_name(english:"Ubuntu 4.10 : libxpm4 vulnerability (USN-27-1)");
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
"Chris Evans discovered several stack overflows in the versions of
libXpm shipped by X.Org, XFree86, and LessTif. These overflows were
fixed in the Warty development tree before its release. Mathieu Herrb
of OpenBSD subsequently discovered that the original patch was
insufficient to address these overflows, and thus the version of
libxpm4 shipped with Warty is still vulnerable to the original
overflows.

These overflows do not allow privilege escalation through the X
server; the overflows are in a client-side library, allowing arbitrary
code execution with the privileges of the user viewing a malicious
pixmap.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lbxproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdps-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdps1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdps1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libice6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libice6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsm6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsm6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx11-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx11-6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxext-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxext6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxext6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxft1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxft1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxi-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxi6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxi6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmu6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmu6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmuu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmuu1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmuu1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxp6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxp6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxpm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxpm4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxpm4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxrandr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxrandr2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxrandr2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxt6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxt6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxtrap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxtrap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxtrap6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxtst-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxtst6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxtst6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxv-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxv1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxv1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:proxymngr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:x-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:x-window-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:x-window-system-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:x-window-system-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xbase-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-100dpi-transcoded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-75dpi-transcoded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-base-transcoded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-cyrillic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-scalable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfree86-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfwp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-dri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-dri-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-gl-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-gl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-glu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-glu-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-glu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibosmesa-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibosmesa4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibosmesa4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-static-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-static-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xmh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xprt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xfree86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xfree86-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xspecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xterm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2004-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"lbxproxy", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libdps-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libdps1", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libdps1-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libice-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libice6", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libice6-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libsm-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libsm6", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libsm6-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libx11-6", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libx11-6-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libx11-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxaw6", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxaw6-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxaw6-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxaw7", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxaw7-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxaw7-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxext-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxext6", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxext6-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxft1", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxft1-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxi-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxi6", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxi6-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxmu-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxmu6", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxmu6-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxmuu-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxmuu1", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxmuu1-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxp-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxp6", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxp6-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxpm-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxpm4", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxpm4-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxrandr-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxrandr2", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxrandr2-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxt-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxt6", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxt6-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxtrap-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxtrap6", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxtrap6-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxtst-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxtst6", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxtst6-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxv-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxv1", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libxv1-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"pm-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"proxymngr", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"twm", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"x-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"x-window-system", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"x-window-system-core", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"x-window-system-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xbase-clients", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xdm", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xfonts-100dpi", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xfonts-100dpi-transcoded", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xfonts-75dpi", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xfonts-75dpi-transcoded", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xfonts-base", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xfonts-base-transcoded", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xfonts-cyrillic", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xfonts-scalable", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xfree86-common", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xfs", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xfwp", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibmesa-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibmesa-dri", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibmesa-dri-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibmesa-gl", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibmesa-gl-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibmesa-gl-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibmesa-glu", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibmesa-glu-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibmesa-glu-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibmesa3", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibmesa3-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibosmesa-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibosmesa4", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibosmesa4-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibs", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibs-data", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibs-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibs-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibs-pic", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibs-static-dev", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xlibs-static-pic", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xmh", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xnest", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xprt", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xserver-common", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xserver-xfree86", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xserver-xfree86-dbg", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xspecs", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xterm", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xutils", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xvfb", pkgver:"4.3.0.dfsg.1-6ubuntu25.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lbxproxy / libdps-dev / libdps1 / libdps1-dbg / libice-dev / etc");
}
