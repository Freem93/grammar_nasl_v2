#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0094.
#

include("compat.inc");

if (description)
{
  script_id(99975);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id("CVE-2017-7228");
  script_osvdb_id(154912);

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2017-0094)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - BUILDINFO: xen
    commit=8ee9cbea8e71c968e602d5b4974601d283d61d28

  - BUILDINFO: QEMU upstream
    commit=fcd17fdf18b95a9e408acc84f6d2b37cf3fc0335

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86: correct create_bounce_frame (Boris Ostrovsky)
    [Orabug: 25927745]

  - x86: discard type information when stealing pages (Boris
    Ostrovsky) 

  - multicall: deal with early exit conditions (Boris
    Ostrovsky) [Orabug: 25927612]

  - BUILDINFO: xen
    commit=66e33522666436a4b6c13fbaa77b4942876bb5f7

  - BUILDINFO: QEMU upstream
    commit=fcd17fdf18b95a9e408acc84f6d2b37cf3fc0335

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - kexec: Add spinlock for the whole hypercall. (Konrad
    Rzeszutek Wilk) 

  - kexec: clear kexec_image slot when unloading kexec image
    (Bhavesh Davda) [Orabug: 25861731]

  - BUILDINFO: xen
    commit=337c8edcc582f8bfb1bcfcb5a475c5fc18ff2def

  - BUILDINFO: QEMU upstream
    commit=fcd17fdf18b95a9e408acc84f6d2b37cf3fc0335

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - memory: properly check guest memory ranges in
    XENMEM_exchange handling (Jan Beulich) [Orabug:
    25760559] (CVE-2017-7228)

  - xenstored: Log when the write transaction rate limit
    bites (Ian Jackson) [Orabug: 25745225]

  - xenstored: apply a write transaction rate limit (Ian
    Jackson) 

  - BUILDINFO: xen
    commit=17b0cd2109c42553e9c8c34d3a2b8252abead104

  - BUILDINFO: QEMU upstream
    commit=fcd17fdf18b95a9e408acc84f6d2b37cf3fc0335

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - xm: Fix the error message displayed by 'xm create ...'
    (Venu Busireddy) [Orabug: 25721696]

  - xm: expand pci hidden devices tools (Venu Busireddy)
    [Orabug: 25721624]

  - BUILDINFO: xen
    commit=81f33e7316b476c319f42eb56ac58fc450804ded

  - BUILDINFO: QEMU upstream
    commit=2e4e0a805aeb448242b43399e0853b851bccde4e

  - BUILDINFO: QEMU traditional
    commit=d9ba4c53b14ebf9a0613b5638f90d95489622f0c

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - xend: fix vif device ID allocation (Zhigang Wang)
    [Orabug: 25692157] 

  - BUILDINFO: xen
    commit=68930e8bbd9311ebd12fdb251362a2e1f9987fba

  - BUILDINFO: QEMU upstream
    commit=f663d3dd4e968756d33e29cb2c2c956cabbdd4ca

  - BUILDINFO: QEMU traditional
    commit=d9ba4c53b14ebf9a0613b5638f90d95489622f0c

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - xend: fix waitForSuspend (Zhigang Wang) [Orabug:
    25638583] [Orabug: 25653480]

  - IOMMU: always call teardown callback (Oleksandr
    Tyshchenko) [Orabug: 25485193]

  - BUILDINFO: xen
    commit=9f3030e391274b89deb80c86a6343dac473916b3

  - BUILDINFO: QEMU upstream
    commit=f663d3dd4e968756d33e29cb2c2c956cabbdd4ca

  - BUILDINFO: QEMU traditional
    commit=d9ba4c53b14ebf9a0613b5638f90d95489622f0c

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - one-off build"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-May/000689.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"xen-4.4.4-105.0.12.el6")) flag++;
if (rpm_check(release:"OVS3.4", reference:"xen-tools-4.4.4-105.0.12.el6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-tools");
}
