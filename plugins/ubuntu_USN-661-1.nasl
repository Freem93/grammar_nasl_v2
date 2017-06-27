#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-661-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37570);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/26 14:35:56 $");

  script_xref(name:"USN", value:"661-1");

  script_name(english:"Ubuntu 8.10 : linux regression (USN-661-1)");
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
"Version 2.6.27 of the Linux kernel changed the order of options in TCP
headers. While this change was RFC-compliant, it was found that some
old routers and consumer DSL modems would not route traffic for these
systems when TCP timestamps were enabled. As a workaround, TCP
timestamps were disabled via sysctl.

This update restores the previous ordering of TCP options, and
reenables TCP timestamps. We apologize for the inconvenience.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:procps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! ereg(pattern:"^(8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.10", pkgname:"libproc-dev", pkgver:"3.2.7-9ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-doc-2.6.27", pkgver:"2.6.27-7.15")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-7", pkgver:"2.6.27-7.15")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-7-generic", pkgver:"2.6.27-7.15")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-7-server", pkgver:"2.6.27-7.15")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-7-generic", pkgver:"2.6.27-7.15")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-7-server", pkgver:"2.6.27-7.15")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-7-virtual", pkgver:"2.6.27-7.15")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-libc-dev", pkgver:"2.6.27-7.15")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-source-2.6.27", pkgver:"2.6.27-7.15")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"procps", pkgver:"1:3.2.7-9ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libproc-dev / linux-doc-2.6.27 / linux-headers-2.6 / etc");
}
