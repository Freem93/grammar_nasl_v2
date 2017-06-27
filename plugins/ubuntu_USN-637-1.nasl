#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-637-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34048);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-0598", "CVE-2008-2812", "CVE-2008-2931", "CVE-2008-3272", "CVE-2008-3275");
  script_bugtraq_id(30076, 30126, 30559, 30647);
  script_xref(name:"USN", value:"637-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : linux, linux-source-2.6.15/20/22 vulnerabilities (USN-637-1)");
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
"It was discovered that there were multiple NULL pointer function
dereferences in the Linux kernel terminal handling code. A local
attacker could exploit this to execute arbitrary code as root, or
crash the system, leading to a denial of service. (CVE-2008-2812)

The do_change_type routine did not correctly validation administrative
users. A local attacker could exploit this to block mount points or
cause private mounts to be shared, leading to denial of service or a
possible loss of privacy. (CVE-2008-2931)

Tobias Klein discovered that the OSS interface through ALSA did not
correctly validate the device number. A local attacker could exploit
this to access sensitive kernel memory, leading to a denial of service
or a loss of privacy. (CVE-2008-3272)

Zoltan Sogor discovered that new directory entries could be added to
already deleted directories. A local attacker could exploit this,
filling up available memory and disk space, leading to a denial of
service. (CVE-2008-3275)

In certain situations, the fix for CVE-2008-0598 from USN-623-1 was
causing infinite loops in the writev syscall. This update corrects the
mistake. We apologize for the inconvenience.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-cell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-openvz");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/26");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-386", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-686", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-generic", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-k8", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-server", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-xeon", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-server", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-386", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-686", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-generic", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-k8", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-server", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-xeon", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-server", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-52.71")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-doc-2.6.20", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17-386", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17-generic", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17-lowlatency", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17-server", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-17-386", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-17-generic", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-17-lowlatency", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-17-server", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-17-386", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-17-generic", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-17-lowlatency", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-17-server", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-kernel-devel", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-libc-dev", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-source-2.6.20", pkgver:"2.6.20-17.39")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-doc-2.6.22", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-386", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-generic", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-rt", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-server", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-ume", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-virtual", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-xen", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-386", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-cell", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-generic", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-lpia", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-lpiacompat", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-rt", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-server", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-ume", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-virtual", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-xen", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-386", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-generic", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-server", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-virtual", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-kernel-devel", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-libc-dev", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-source-2.6.22", pkgver:"2.6.22-15.58")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-386", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-generic", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-openvz", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-rt", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-server", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-virtual", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-xen", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-386", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-generic", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-lpia", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-lpiacompat", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-openvz", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-rt", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-server", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-virtual", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-xen", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-19-386", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-19-generic", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-19-server", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-19-virtual", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-19.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-19.41")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.15 / linux-doc-2.6.20 / linux-doc-2.6.22 / etc");
}
