#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2766 and 
# Oracle Linux Security Advisory ELSA-2016-2766 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(94908);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/07 21:08:18 $");

  script_cve_id("CVE-2016-1583", "CVE-2016-2143");
  script_osvdb_id(135975, 139987);
  script_xref(name:"RHSA", value:"2016:2766");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2016-2766)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2766 :

An update for kernel is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* It was found that stacking a file system over procfs in the Linux
kernel could lead to a kernel stack overflow due to deep nesting, as
demonstrated by mounting ecryptfs over procfs and creating a recursion
by mapping /proc/environ. An unprivileged, local user could
potentially use this flaw to escalate their privileges on the system.
(CVE-2016-1583, Important)

* It was reported that on s390x, the fork of a process with four page
table levels will cause memory corruption with a variety of symptoms.
All processes are created with three level page table and a limit of
4TB for the address space. If the parent process has four page table
levels with a limit of 8PB, the function that duplicates the address
space will try to copy memory areas outside of the address space limit
for the child process. (CVE-2016-2143, Moderate)

Bug Fix(es) :

* Use of a multi-threaded workload with high memory mappings sometiems
caused a kernel panic, due to a race condition between the context
switch and the pagetable upgrade. This update fixes the switch_mm() by
using the complete asce parameter instead of the asce_bits parameter.
As a result, the kernel no longer panics in the described scenario.
(BZ#1377472)

* When iptables created the Transmission Control Protocol (TCP) reset
packet, a kernel crash could occur due to uninitialized pointer to the
TCP header within the Socket Buffer (SKB). This update fixes the
transport header pointer in TCP reset for both IPv4 and IPv6, and the
kernel no longer crashes in the described situation.(BZ#1372266)

* Previously, when the Enhanced Error Handling (EEH) mechanism did not
block the PCI configuration space access and an error was detected, a
kernel panic occurred. This update fixes EEH to fix this problem. As a
result, the kernel no longer panics in the described scenario.
(BZ#1379596)

* When the lockd service failed to start up completely, the notifier
blocks were in some cases registered on a notification chain multiple
times, which caused the occurrence of a circular list on the
notification chain. Consequently, a soft lock-up or a kernel oops
occurred. With this update, the notifier blocks are unregistered if
lockd fails to start up completely, and the soft lock-ups or the
kernel oopses no longer occur under the described circumstances.
(BZ#1375637)

* When the Fibre Channel over Ethernet (FCoE) was configured, the FCoE
MaxFrameSize parameter was incorrectly restricted to 1452. With this
update, the NETIF_F_ALL_FCOE symbol is no longer ignored, which fixes
this bug. MaxFrameSize is now restricted to 2112, which is the correct
value. (BZ#1381592)

* When the fnic driver was installed on Cisco UCS Blade Server, the
discs were under certain circumstances put into the offline state with
the following error message: 'Medium access timeout failure. Offlining
disk!'. This update fixes fnic to set the Small Computer System
Interface (SCSI) status as DID_ABORT after a successful abort
operation. As a result, the discs are no longer put into the offlined
state in the described situation. (BZ#1382620)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006512.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:X/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL6", rpm:"kernel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-2.6.32-642.11.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-abi-whitelists-2.6.32") && rpm_check(release:"EL6", reference:"kernel-abi-whitelists-2.6.32-642.11.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-2.6.32-642.11.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-devel-2.6.32-642.11.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-devel-2.6.32-642.11.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-doc-2.6.32-642.11.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-firmware-2.6.32-642.11.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-headers-2.6.32-642.11.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"perf-2.6.32-642.11.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"python-perf-2.6.32-642.11.1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
