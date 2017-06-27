#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-577-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31092);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/10/26 14:35:56 $");

  script_cve_id("CVE-2008-0600");
  script_bugtraq_id(27801);
  script_xref(name:"USN", value:"577-1");

  script_name(english:"Ubuntu 6.10 / 7.04 / 7.10 : linux-source-2.6.17/20/22 vulnerability (USN-577-1)");
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
"Wojciech Purczynski discovered that the vmsplice system call did not
properly perform verification of user-memory pointers. A local
attacker could exploit this to overwrite arbitrary kernel memory and
gain root privileges. (CVE-2008-0600).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-cell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.22");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.10", pkgname:"linux-doc-2.6.17", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-386", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-generic", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-server", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-386", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-generic", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-server", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-386", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-generic", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-server", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-kdump", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-kernel-devel", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-libc-dev", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-source-2.6.17", pkgver:"2.6.17.1-12.44")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-doc-2.6.20", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-386", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-generic", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-lowlatency", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-server", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-386", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-generic", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-lowlatency", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-server", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-386", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-generic", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-lowlatency", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-server", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-kernel-devel", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-libc-dev", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-source-2.6.20", pkgver:"2.6.20-16.35")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-doc-2.6.22", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-386", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-generic", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-rt", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-server", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-ume", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-virtual", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-xen", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-386", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-cell", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-generic", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-lpia", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-lpiacompat", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-rt", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-server", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-ume", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-virtual", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-xen", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-14-386", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-14-generic", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-14-server", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-14-virtual", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-kernel-devel", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-libc-dev", pkgver:"2.6.22-14.52")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-source-2.6.22", pkgver:"2.6.22-14.52")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.17 / linux-doc-2.6.20 / linux-doc-2.6.22 / etc");
}
