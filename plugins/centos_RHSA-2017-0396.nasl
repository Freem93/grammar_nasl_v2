#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0396 and 
# CentOS Errata and Security Advisory 2017:0396 respectively.
#

include("compat.inc");

if (description)
{
  script_id(97528);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/07 17:46:31 $");

  script_cve_id("CVE-2017-2615", "CVE-2017-2620");
  script_osvdb_id(151241, 152349);
  script_xref(name:"RHSA", value:"2017:0396");
  script_xref(name:"IAVB", value:"2017-B-0024");

  script_name(english:"CentOS 7 : qemu-kvm (CESA-2017:0396)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for qemu-kvm is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Kernel-based Virtual Machine (KVM) is a full virtualization solution
for Linux on a variety of architectures. The qemu-kvm packages provide
the user-space component for running virtual machines that use KVM.

Security Fix(es) :

* Quick emulator (QEMU) built with the Cirrus CLGD 54xx VGA emulator
support is vulnerable to an out-of-bounds access issue. It could occur
while copying VGA data via bitblt copy in backward mode. A privileged
user inside a guest could use this flaw to crash the QEMU process
resulting in DoS or potentially execute arbitrary code on the host
with privileges of QEMU process on the host. (CVE-2017-2615)

* Quick emulator (QEMU) built with the Cirrus CLGD 54xx VGA Emulator
support is vulnerable to an out-of-bounds access issue. The issue
could occur while copying VGA data in cirrus_bitblt_cputovideo. A
privileged user inside guest could use this flaw to crash the QEMU
process OR potentially execute arbitrary code on host with privileges
of the QEMU process. (CVE-2017-2620)

Red Hat would like to thank Wjjzhang (Tencent.com Inc.) and Li Qiang
(360.cn Inc.) for reporting CVE-2017-2615.

Bug Fix(es) :

* When using the virtio-blk driver on a guest virtual machine with no
space on the virtual hard drive, the guest terminated unexpectedly
with a 'block I/O error in device' message and the qemu-kvm process
exited with a segmentation fault. This update fixes how the
system_reset QEMU signal is handled in the above scenario. As a
result, if a guest crashes due to no space left on the device,
qemu-kvm continues running and the guest can be reset as expected.
(BZ#1420049)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-March/022321.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c0c33e2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-kvm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-img-1.5.3-126.el7_3.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-1.5.3-126.el7_3.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-126.el7_3.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-126.el7_3.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
