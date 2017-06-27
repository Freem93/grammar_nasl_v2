#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-319-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27896);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/10/26 14:26:01 $");

  script_cve_id("CVE-2006-3626");
  script_bugtraq_id(18992);
  script_xref(name:"USN", value:"319-2");

  script_name(english:"Ubuntu 5.04 / 5.10 : linux-source-2.6.10, linux-source-2.6.12 vulnerability (USN-319-2)");
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
"USN-319-1 fixed a Linux kernel vulnerability in Ubuntu 6.06 LTS. This
followup advisory provides the corresponding updates for Ubuntu 5.04
and 5.10.

For reference, these are the details of the original USN :

A race condition has been discovered in the file permission handling
of the /proc file system. A local attacker could exploit this to
execute arbitrary code with full root privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-ubuntu-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-ubuntu-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/19");
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
if (! ereg(pattern:"^(5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"linux-doc-2.6.10", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-386", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-686", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-686-smp", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-generic", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-k8", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-k8-smp", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-xeon", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-386", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-686", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-686-smp", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-generic", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-k8", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-k8-smp", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-xeon", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-patch-ubuntu-2.6.10", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-source-2.6.10", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-tree-2.6.10", pkgver:"2.6.10-34.22")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-doc-2.6.12", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-386", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686-smp", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-386", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686-smp", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-patch-ubuntu-2.6.12", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-source-2.6.12", pkgver:"2.6.12-10.36")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-tree-2.6.12", pkgver:"2.6.12-10.36")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.10 / linux-doc-2.6.12 / linux-headers-2.6 / etc");
}
