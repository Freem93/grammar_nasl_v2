#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0217. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96922);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/02/03 14:37:47 $");

  script_cve_id("CVE-2016-2847", "CVE-2016-7117");
  script_osvdb_id(135194, 145048);
  script_xref(name:"RHSA", value:"2017:0217");

  script_name(english:"RHEL 7 : kernel (RHSA-2017:0217)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.2
Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* A use-after-free vulnerability was found in the kernel's socket
recvmmsg subsystem. This may allow remote attackers to corrupt memory
and may allow execution of arbitrary code. This corruption takes place
during the error handling routines within __sys_recvmmsg() function.
(CVE-2016-7117, Important)

* It is possible for a single process to cause an OOM condition by
filling large pipes with data that are never read. A typical process
filling 4096 pipes with 1 MB of data will use 4 GB of memory and there
can be multiple such processes, up to a per-user-limit.
(CVE-2016-2847, Moderate)

Red Hat would like to thank Tetsuo Handa for reporting CVE-2016-2847.

Bug Fix(es) :

* Previously, an XFS corruption in some cases occurred on Seagate 8TB
drive based volumes after a planned system shutdown or reboot, when a
disk write back cache was used. With this update, the megaraid_sas
driver has been fixed and the XFS corruption no longer occurs in the
described scenario. (BZ#1398178)

* This update applies a set of patches for the resizable hash table
(rhashtable). This set contains backported bug fixes and enhancements
from upstream. (BZ#1382630)

* Previously, a kernel panic in some cases occurred during the boot
with the Nonvolatile Memory Express (NVMe) kernel module, because the
NVMe driver did not receive legacy PCI interrupts. This update fixes
the NVMe driver to always use the Message Signaled Interrupts
(MSI/MSI-X) interrupts. As a result, the operating system now boots
without panic under the described circumstances. (BZ#1396558)

* Previously, the Advanced Error Reporting (AER) correct error in some
cases caused a kernel panic. This update fixes the
_scsih_pci_mmio_enabled() function in the mpt3sas driver to not
incorrectly return PCI_ERS_RESULT_NEED_RESET return value in the
situation when PCI_ERS_RESULT_RECOVERED return value is expected. As a
result, the kernel no longer panics due to _scsih_pci_mmio_enabled().
(BZ#1395220)

* When resizing the Transmit (TX) and Receive (RX) rings in the sfc
driver with the 'ethtool -G' command, a kernel protection fault in the
napi_hash_add() function occurred on systems with a large number of
queues. With this update, the efx_copy_channel()function in the sfc
driver has been fixed to correctly clear the napi_hash state. As a
result, the sfc kernel module now unloads successfully without the
mentioned kernel protection fault. (BZ#1401460)

* When a virtual machine (VM) with 2 PCI-Passthrough Ethernet
interfaces attached was created, deleted and recreated, the operating
system terminated unexpectedly and rebooted during the recreation.
This update fixes the race condition between the eventfd and virqfd
signaling mechanisms in the vfio driver. As a result, the operating
system now boots without crashing in the described situation.
(BZ#1391610)

* Previously, when two NFS shares with different security settings
were mounted, the I/O operations to the kerberos-authenticated mount
caused the RPC_CRED_KEY_EXPIRE_SOON parameter to be set, but the
parameter was not unset when performing the I/O operations on the
sec=sys mount. Consequently, writes to both NFS shares had the same
parameters, regardless of their security settings. This update fixes
this problem by moving the NO_CRKEY_TIMEOUT parameter to the
auth->au_flags field. As a result, NFS shares with different security
settings are now handled as expected. (BZ#1388603)

* Previously, memory corruption by copying data into the wrong memory
locations sometimes occurred, because the __copy_tofrom_user()
function was returning incorrect values. This update fixes the
__copy_tofrom_user() function so that it no longer returns larger
values than the number of bytes it was asked to copy. As a result,
memory corruption no longer occurs in he described scenario.
(BZ#1398588)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2847.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-7117.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/2706661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0217.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^7\.2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.2", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:0217";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"kernel-abi-whitelists-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debug-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-devel-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"kernel-doc-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-headers-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-kdump-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"perf-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"perf-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"perf-debuginfo-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"python-perf-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"python-perf-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-327.46.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-327.46.1.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
