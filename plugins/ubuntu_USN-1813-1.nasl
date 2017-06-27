#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1813-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66302);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/26 14:05:58 $");

  script_cve_id("CVE-2012-6548", "CVE-2012-6549", "CVE-2013-0913", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1848", "CVE-2013-1860", "CVE-2013-2634", "CVE-2013-2635");
  script_bugtraq_id(58427, 58510, 58597, 58600, 58604, 58605, 58607, 58700, 58993, 58994);
  script_xref(name:"USN", value:"1813-1");

  script_name(english:"Ubuntu 12.10 : linux vulnerabilities (USN-1813-1)");
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
"Mathias Krause discovered an information leak in the Linux kernel's
UDF file system implementation. A local user could exploit this flaw
to examine some of the kernel's heap memory. (CVE-2012-6548)

Mathias Krause discovered an information leak in the Linux kernel's
ISO 9660 CDROM file system driver. A local user could exploit this
flaw to examine some of the kernel's heap memory. (CVE-2012-6549)

An integer overflow was discovered in the Direct Rendering Manager
(DRM) subsystem for the i915 video driver in the Linux kernel. A local
user could exploit this flaw to cause a denial of service (crash) or
potentially escalate privileges. (CVE-2013-0913)

Andrew Honig discovered a flaw in guest OS time updates in the Linux
kernel's KVM (Kernel-based Virtual Machine). A privileged guest user
could exploit this flaw to cause a denial of service (crash host
system) or potential escalate privilege to the host kernel level.
(CVE-2013-1796)

Andrew Honig discovered a use after free error in guest OS time
updates in the Linux kernel;s KVM (Kernel-based Virtual Machine). A
privileged guest user could exploit this flaw to escalate privilege to
the host kernel level. (CVE-2013-1797)

Andrew Honig reported a flaw in the way KVM (Kernel-based Virtual
Machine) emulated the IOAPIC. A privileged guest user could exploit
this flaw to read host memory or cause a denial of service (crash the
host). (CVE-2013-1798)

A format-string bug was discovered in the Linux kernel's ext3
filesystem driver. A local user could exploit this flaw to possibly
escalate privileges on the system. (CVE-2013-1848)

A buffer overflow was discovered in the Linux Kernel's USB subsystem
for devices reporting the cdc-wdm class. A specially crafted USB
device when plugged-in could cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2013-1860)

An information leak in the Linux kernel's dcb netlink interface was
discovered. A local user could obtain sensitive information by
examining kernel stack memory. (CVE-2013-2634)

A kernel stack information leak was discovered in the RTNETLINK
component of the Linux kernel. A local user could read sensitive
information from the kernel stack. (CVE-2013-2635).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.5-generic and / or
linux-image-3.5-highbank packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.5-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.5-highbank");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.10", pkgname:"linux-image-3.5.0-28-generic", pkgver:"3.5.0-28.48")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"linux-image-3.5.0-28-highbank", pkgver:"3.5.0-28.48")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.5-generic / linux-image-3.5-highbank");
}
