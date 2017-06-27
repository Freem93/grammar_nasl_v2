#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2445-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80031);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/26 14:16:26 $");

  script_cve_id("CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-7825", "CVE-2014-7826", "CVE-2014-8134", "CVE-2014-8369", "CVE-2014-9090");
  script_bugtraq_id(70749, 70766, 70768, 70883, 70971, 70972, 71250);
  script_osvdb_id(113724, 113726, 113727, 113728, 114369, 114370, 115163, 115870);
  script_xref(name:"USN", value:"2445-1");

  script_name(english:"Ubuntu 12.04 LTS : linux-lts-trusty vulnerabilities (USN-2445-1)");
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
"An information leak in the Linux kernel was discovered that could leak
the high 16 bits of the kernel stack address on 32-bit Kernel Virtual
Machine (KVM) paravirt guests. A user in the guest OS could exploit
this leak to obtain information that could potentially be used to aid
in attacking the kernel. (CVE-2014-8134)

Rabin Vincent, Robert Swiecki, Russell King discovered that the ftrace
subsystem of the Linux kernel does not properly handle private syscall
numbers. A local user could exploit this flaw to cause a denial of
service (OOPS). (CVE-2014-7826)

A flaw in the handling of malformed ASCONF chunks by SCTP (Stream
Control Transmission Protocol) implementation in the Linux kernel was
discovered. A remote attacker could exploit this flaw to cause a
denial of service (system crash). (CVE-2014-3673)

A flaw in the handling of duplicate ASCONF chunks by SCTP (Stream
Control Transmission Protocol) implementation in the Linux kernel was
discovered. A remote attacker could exploit this flaw to cause a
denial of service (panic). (CVE-2014-3687)

It was discovered that excessive queuing by SCTP (Stream Control
Transmission Protocol) implementation in the Linux kernel can cause
memory pressure. A remote attacker could exploit this flaw to cause a
denial of service. (CVE-2014-3688)

Rabin Vincent, Robert Swiecki, Russell Kinglaw discovered a flaw in
how the perf subsystem of the Linux kernel handles private systecall
numbers. A local user could exploit this to cause a denial of service
(OOPS) or bypass ASLR protections via a crafted application.
(CVE-2014-7825)

The KVM (kernel virtual machine) subsystem of the Linux kernel
miscalculates the number of memory pages during the handling of a
mapping failure. A guest OS user could exploit this to cause a denial
of service (host OS page unpinning) or possibly have unspecified other
impact by leveraging guest OS privileges. (CVE-2014-8369)

Andy Lutomirski discovered that the Linux kernel does not properly
handle faults associated with the Stack Segment (SS) register on the
x86 architecture. A local attacker could exploit this flaw to cause a
denial of service (panic). (CVE-2014-9090).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.13-generic and / or
linux-image-3.13-generic-lpae packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.13.0-43-generic", pkgver:"3.13.0-43.72~precise1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.13.0-43-generic-lpae", pkgver:"3.13.0-43.72~precise1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.13-generic / linux-image-3.13-generic-lpae");
}
