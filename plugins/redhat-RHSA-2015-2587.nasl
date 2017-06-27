#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2587. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88572);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/01/06 16:11:33 $");

  script_cve_id("CVE-2015-2925", "CVE-2015-5307", "CVE-2015-7613");
  script_osvdb_id(120327, 128379, 130090);
  script_xref(name:"RHSA", value:"2015:2587");

  script_name(english:"RHEL 7 : kernel (RHSA-2015:2587)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix three security issues, several bugs,
and one enhancement are now available for Red Hat Enterprise Linux 7.1
Extended Update Support.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way the Linux kernel's file system
implementation handled rename operations in which the source was
inside and the destination was outside of a bind mount. A privileged
user inside a container could use this flaw to escape the bind mount
and, potentially, escalate their privileges on the system.
(CVE-2015-2925, Important)

* It was found that the x86 ISA (Instruction Set Architecture) is
prone to a denial of service attack inside a virtualized environment
in the form of an infinite loop in the microcode due to the way
(sequential) delivering of benign exceptions such as #AC (alignment
check exception) is handled. A privileged user inside a guest could
use this flaw to create denial of service conditions on the host
kernel. (CVE-2015-5307, Important)

* A race condition flaw was found in the way the Linux kernel's IPC
subsystem initialized certain fields in an IPC object structure that
were later used for permission checking before inserting the object
into a globally visible list. A local, unprivileged user could
potentially use this flaw to elevate their privileges on the system.
(CVE-2015-7613, Important)

Red Hat would like to thank Ben Serebrin of Google Inc. for reporting
the CVE-2015-5307 issue.

This update also fixes the following bugs and adds one enhancement :

* When setting up an ESP IPsec connection, the aes_ctr algorithm did
not work for ESP on a Power little endian VM host. As a consequence, a
kernel error was previously returned and the connection failed to be
established. A set of patches has been provided to fix this bug, and
aes_ctr works for ESP in the described situation as expected.
(BZ#1247127)

* The redistribute3() function distributed entries across 3 nodes.
However, some entries were moved an incorrect way, breaking the
ordering. As a result, BUG() in the dm-btree-remove.c:shift() function
occurred when entries were removed from the btree. A patch has been
provided to fix this bug, and redistribute3() now works as expected.
(BZ#1263945)

* When booting an mpt2sas adapter in a huge DDW enabled slot on Power,
the kernel previously generated a warning followed by a call trace.
The provided patch set enhances the Power kernel to be able to support
IOMMU as a fallback for the cases where the coherent mask of the
device is not suitable for direct DMA. As a result, neither the
warning nor the call trace occur in this scenario. (BZ#1267133)

* If the client mounted /exports and tried to execute the 'chown -R'
command across the entire mountpoint, a warning about a circular
directory structure was previously returned because mount points all
had the same inode number. A set of patches has been provided to fix
this bug, and mount points are now assigned with unique inode numbers
as expected. (BZ#1273239)

* Due to a validation error of in-kernel MMIO tracing, a VM became
previously unresponsive when connected to Red Hat Enterprise
Virtualization Hypervisor. The provided patch fixes this bug by
dropping the check in MMIO handler, and a VM continues running as
expected. (BZ#1275149)

* The NFS client could previously fail to send a CLOSE operation if
the file was opened with O_WRONLY and the server restarted after the
OPEN. Consequently, the server appeared in a state that could block
other NFS operations from completing. The client's state flags have
been modified to catch this condition and correctly CLOSE the file.
(BZ#1275298)

* This update sets multicast filters for multicast packets when the
interface is not in promiscuous mode. This change has an impact on the
RAR usage such that SR-IOV has some RARs reserved for its own usage as
well. (BZ#1265091)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add this
enhancement. The system must be rebooted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2925.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5307.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7613.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2587.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2587";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"kernel-abi-whitelists-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-debug-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-debug-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-devel-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-devel-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"kernel-doc-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-headers-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-headers-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-kdump-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-tools-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"perf-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"perf-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"perf-debuginfo-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"python-perf-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"python-perf-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-229.24.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-229.24.2.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
