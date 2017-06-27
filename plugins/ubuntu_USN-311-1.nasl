#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-311-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27886);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/10/26 14:26:01 $");

  script_cve_id("CVE-2006-0039", "CVE-2006-2445", "CVE-2006-2448", "CVE-2006-2451");
  script_bugtraq_id(18874);
  script_osvdb_id(25697, 26946, 26947, 27030);
  script_xref(name:"USN", value:"311-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : linux-source-2.6.10/-2.6.12/-2.6.15 vulnerabilities (USN-311-1)");
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
"A race condition was discovered in the do_add_counters() functions.
Processes which do not run with full root privileges, but have the
CAP_NET_ADMIN capability can exploit this to crash the machine or read
a random piece of kernel memory. In Ubuntu there are no packages that
are affected by this, so this can only be an issue for you if you use
third-party software that uses Linux capabilities. (CVE-2006-0039)

John Stultz discovered a faulty BUG_ON trigger in the handling of
POSIX timers. A local attacker could exploit this to trigger a kernel
oops and crash the machine. (CVE-2006-2445)

Dave Jones discovered that the PowerPC kernel did not perform certain
required access_ok() checks. A local user could exploit this to read
arbitrary kernel memory and crash the kernel on 64-bit systems, and
possibly read arbitrary kernel memory on 32-bit systems.
(CVE-2006-2448)

A design flaw was discovered in the prctl(PR_SET_DUMPABLE, ...) system
call, which allowed a local user to have core dumps created in a
directory he could not normally write to. This could be exploited to
drain available disk space on system partitions, or, under some
circumstances, to execute arbitrary code with full root privileges.
This flaw only affects Ubuntu 6.06 LTS. (CVE-2006-2451)

In addition, the Ubuntu 6.06 LTS update fixes a range of bugs.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.15-26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-control");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-ubuntu-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-ubuntu-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-legacy-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/22");
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
if (! ereg(pattern:"^(5\.04|5\.10|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"linux-doc-2.6.10", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-386", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-686", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-686-smp", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-generic", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-k8", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-k8-smp", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-xeon", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-386", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-686", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-686-smp", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-generic", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-k8", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-k8-smp", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-xeon", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-patch-ubuntu-2.6.10", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-source-2.6.10", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-tree-2.6.10", pkgver:"2.6.10-34.21")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-doc-2.6.12", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-386", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686-smp", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-386", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686-smp", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-patch-ubuntu-2.6.12", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-source-2.6.12", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-tree-2.6.12", pkgver:"2.6.12-10.35")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-firmware", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-firmware-2.6.15-26", pkgver:"3.11+2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-control", pkgver:"8.25.18+2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-kernel-source", pkgver:"8.25.18+2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-386", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-686", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-686-smp", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-generic", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-k8", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-k8-smp", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-server", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-xeon", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-doc", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-386", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-686", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-amd64-generic", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-amd64-k8", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-amd64-server", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-amd64-xeon", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-server", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-386", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-686", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-generic", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-k8", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-server", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-xeon", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-server", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-386", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-686", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-amd64-generic", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-amd64-k8", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-amd64-server", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-amd64-xeon", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-server", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-386", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-686", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-generic", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-k8", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-server", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-xeon", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-server", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-26-386", pkgver:"2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-26-686", pkgver:"2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-26-amd64-generic", pkgver:"2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-26-amd64-k8", pkgver:"2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-26-amd64-xeon", pkgver:"2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-386", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-686", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-amd64-generic", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-amd64-k8", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-amd64-xeon", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-common", pkgver:"2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-server", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source", pkgver:"2.6.15.24")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-26.44")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx", pkgver:"1.0.8762+2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-dev", pkgver:"1.0.8762+2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy", pkgver:"1.0.7174+2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy-dev", pkgver:"1.0.7174+2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-kernel-source", pkgver:"1.0.8762+2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7174+2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx", pkgver:"7.0.0-8.25.18+2.6.15.11-3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.0.0-8.25.18+2.6.15.11-3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avm-fritz-firmware / avm-fritz-firmware-2.6.15-26 / etc");
}
