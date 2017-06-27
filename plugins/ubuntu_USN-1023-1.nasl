#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1023-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50843);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/26 14:05:56 $");

  script_cve_id("CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-4082");
  script_bugtraq_id(45072);
  script_osvdb_id(70262);
  script_xref(name:"USN", value:"1023-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : linux, linux-{ec2,source-2.6.15} vulnerabilities (USN-1023-1)");
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
"Nelson Elhage discovered several problems with the Acorn Econet
protocol driver. A local user could cause a denial of service via a
NULL pointer dereference, escalate privileges by overflowing the
kernel stack, and assign Econet addresses to arbitrary interfaces.
(CVE-2010-3848, CVE-2010-3849, CVE-2010-3850)

Dan Rosenberg discovered that the VIA video driver did not correctly
clear kernel memory. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-4082).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-source-2.6.31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-source-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-386", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-686", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-server", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-server", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-386", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-686", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-server", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-server", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-55.90")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-386", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-generic", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-openvz", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-rt", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-server", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-virtual", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-xen", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-386", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-generic", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-lpia", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-lpiacompat", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-openvz", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-rt", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-server", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-virtual", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-xen", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-28-386", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-28-generic", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-28-server", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-28-virtual", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-28.81")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-doc", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-ec2-doc", pkgver:"2.6.31-307.22")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-ec2-source-2.6.31", pkgver:"2.6.31-307.22")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-386", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-generic", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-generic-pae", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-server", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-307", pkgver:"2.6.31-307.22")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-307-ec2", pkgver:"2.6.31-307.22")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-386", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-generic", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-generic-pae", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-lpia", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-server", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-virtual", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-307-ec2", pkgver:"2.6.31-307.22")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-libc-dev", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-source-2.6.31", pkgver:"2.6.31-22.69")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-doc", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-ec2-doc", pkgver:"2.6.32-310.21")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-ec2-source-2.6.32", pkgver:"2.6.32-310.21")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-26", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-26-386", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-26-generic", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-26-generic-pae", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-26-preempt", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-26-server", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-310", pkgver:"2.6.32-310.21")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-310-ec2", pkgver:"2.6.32-310.21")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-26-386", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-26-generic", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-26-generic-pae", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-26-lpia", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-26-preempt", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-26-server", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-26-versatile", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-26-virtual", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-310-ec2", pkgver:"2.6.32-310.21")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-libc-dev", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-source-2.6.32", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-tools-2.6.32-26", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-tools-common", pkgver:"2.6.32-26.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-doc", pkgver:"2.6.35-23.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-23", pkgver:"2.6.35-23.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-23-generic", pkgver:"2.6.35-23.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-23-generic-pae", pkgver:"2.6.35-23.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-23-server", pkgver:"2.6.35-23.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-23-virtual", pkgver:"2.6.35-23.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-23-generic", pkgver:"2.6.35-23.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-23-generic-pae", pkgver:"2.6.35-23.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-23-server", pkgver:"2.6.35-23.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-23-versatile", pkgver:"2.6.35-23.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-23-virtual", pkgver:"2.6.35-23.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-libc-dev", pkgver:"2.6.35-1023.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-source-2.6.35", pkgver:"2.6.35-23.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-tools-2.6.35-23", pkgver:"2.6.35-23.41")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-tools-common", pkgver:"2.6.35-23.41")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc / linux-doc-2.6.15 / linux-doc-2.6.24 / linux-ec2-doc / etc");
}
