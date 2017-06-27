#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1057-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51870);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/26 14:05:56 $");

  script_cve_id("CVE-2010-2943", "CVE-2010-3297", "CVE-2010-4072");
  script_bugtraq_id(42527, 43229, 45054);
  script_osvdb_id(68303, 68306);
  script_xref(name:"USN", value:"1057-1");

  script_name(english:"Ubuntu 6.06 LTS : linux-source-2.6.15 vulnerabilities (USN-1057-1)");
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
"Dave Chinner discovered that the XFS filesystem did not correctly
order inode lookups when exported by NFS. A remote attacker could
exploit this to read or write disk blocks that had changed file
assignment or had become unlinked, leading to a loss of privacy.
(CVE-2010-2943)

Dan Rosenberg discovered that several network ioctls did not clear
kernel memory correctly. A local user could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-3297)

Kees Cook and Vasiliy Kulikov discovered that the shm interface did
not clear kernel memory correctly. A local attacker could exploit this
to read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4072).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-386", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-686", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-server", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-server", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-386", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-686", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-server", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-server", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-55.91")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-55.91")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.15 / linux-headers-2.6 / linux-headers-2.6-386 / etc");
}
