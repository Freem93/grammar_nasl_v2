#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0501. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97750);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id("CVE-2017-6074");
  script_osvdb_id(152302);
  script_xref(name:"RHSA", value:"2017:0501");

  script_name(english:"RHEL 7 : kernel (RHSA-2017:0501)");
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

* A use-after-free flaw was found in the way the Linux kernel's
Datagram Congestion Control Protocol (DCCP) implementation freed SKB
(socket buffer) resources for a DCCP_PKT_REQUEST packet when the
IPV6_RECVPKTINFO option is set on the socket. A local, unprivileged
user could use this flaw to alter the kernel memory, allowing them to
escalate their privileges on the system. (CVE-2017-6074, Important)

Red Hat would like to thank Andrey Konovalov (Google) for reporting
this issue.

Bug Fix(es) :

* Previously, running the 'ethtool -S' command to get the statistics
of a Brocade Network Adapter (BNA) sometimes caused a kernel panic.
This update applies a set of patches to the bna driver, and the kernel
panic no longer occurs in the described scenario. (BZ#1408130)

* Use of a multi-threaded workload with high memory mappings sometimes
caused a kernel panic, due to a race condition between the context
switch and the pagetable upgrade. This update fixes the switch_mm() by
using the complete asce parameter instead of the asce_bits parameter.
As a result, the kernel no longer panics in the described scenario.
(BZ#1410865)

* Previously, the kernel was sending a Transmission Control Protocol
(TCP) window which had a size of zero for a socket with an empty
receive queue. Consequently, the TCP session became unresponsive. This
update fixes the ibmveth driver to set correct values of the gso_size
and gso_type variables and to calculate the value of the gso_segs
variable for large packets. As a result, the TCP session no longer
hangs in the described scenario. (BZ#1411381)

* Previously, booting a kdump kernel in some cases failed with this
error :

Kernel panic - not syncing: Watchdog detected hard LOCKUP on CPU 0.

This update ensures that the hpet timer software counters, including
hpet_default_delta and hpet_t1_cmp, are initialized before an
interrupt request is registered, and the kdump kernel now boots
without the mentioned error message. (BZ#1404183)

* When one of the drives became unresponsive, all other drives
intermittently hung, because the megaraid_sas driver incorrectly sent
a reset request to the PowerEdge RAID Controller (PERC). This update
fixes megaraid_sas, and thus the hang of one drive no longer leads to
intermittent loss of access to all drives on the system. (BZ#1398174)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-6074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0501.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");
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
  rhsa = "RHSA-2017:0501";
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
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"kernel-abi-whitelists-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debug-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-devel-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"kernel-doc-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-headers-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-kdump-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"perf-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"perf-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"perf-debuginfo-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"python-perf-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"python-perf-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-327.49.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-327.49.2.el7")) flag++;

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
