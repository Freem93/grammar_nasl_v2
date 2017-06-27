#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0103. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88558);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/01/10 20:34:11 $");

  script_cve_id("CVE-2015-1805", "CVE-2015-8104", "CVE-2016-0728", "CVE-2016-0774");
  script_osvdb_id(122968, 130089, 133126);
  script_xref(name:"RHSA", value:"2016:0103");

  script_name(english:"RHEL 7 : kernel (RHSA-2016:0103)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix three security issues, multiple bugs,
and one enhancement are now available for Red Hat Enterprise Linux 7.1
Extended Update Support.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* It was found that the x86 ISA (Instruction Set Architecture) is
prone to a denial of service attack inside a virtualized environment
in the form of an infinite loop in the microcode due to the way
(sequential) delivering of benign exceptions such as #DB (debug
exception) is handled. A privileged user inside a guest could use this
flaw to create denial of service conditions on the host kernel.
(CVE-2015-8104, Important)

* A use-after-free flaw was found in the way the Linux kernel's key
management subsystem handled keyring object reference counting in
certain error path of the join_session_keyring() function. A local,
unprivileged user could use this flaw to escalate their privileges on
the system. (CVE-2016-0728, Important)

* It was found that the fix for CVE-2015-1805 incorrectly kept buffer
offset and buffer length in sync on a failed atomic read, potentially
resulting in a pipe buffer state corruption. A local, unprivileged
user could use this flaw to crash the system or leak kernel memory to
user space. (CVE-2016-0774, Moderate)

Red Hat would like to thank the Perception Point research team for
reporting the CVE-2016-0728 issue. The security impact of the
CVE-2016-0774 issue was discovered by Red Hat.

Bug fixes :

* NMI watchdog of guests using legacy LVT0-based NMI delivery did not
work with APICv. Now, NMI works with LVT0 regardless of APICv.
(BZ#1244726)

* Parallel file-extending direct I/O writes could previously race to
update the size of the file. If they executed out-of-order, the file
size could move backwards and push a previously completed write beyond
the end of the file, causing it to be lost. (BZ#1258942)

* The GHES NMI handler had a global spin lock that significantly
increased the latency of each perf sample collection. This update
simplifies locking inside the handler. (BZ#1280200)

* Sometimes, iptables rules are updated along with ip rules, and
routes are reloaded. Previously, skb->sk was mistakenly attached to
some IPv6 forwarding traffic packets, which could cause kernel panic.
Now, such packets are checked and not processed. (BZ#1281700)

* The NUMA node was not reported for PCI adapters, which affected
every POWER system deployed with Red Hat Enterprise Linux 7 and caused
significant decrease in the system performance. (BZ#1283525)

* Processing packets with a lot of different IPv6 source addresses
caused the kernel to return warnings concerning soft-lockups due to
high lock contention and latency increase. (BZ#1285369)

* Running edge triggered interrupts with an ack notifier when
simultaneously reconfiguring the Intel I/O IOAPIC did not work
correctly, so EOI in the interrupt did not cause a VM to exit if APICv
was enabled. Consequently, the VM sometimes became unresponsive.
(BZ#1287001)

* Block device readahead was artificially limited, so the read
performance was poor, especially on RAID devices. Now, per-device
readahead limits are used for each device, which has improved read
performance. (BZ#1287548)

* Identical expectations could not be tracked simultaneously even if
they resided in different connection tracking zones. Now, an
expectation insert attempt is rejected only if the zone is also
identical. (BZ#1290093)

* The storvsc kernel driver for Microsoft Hyper-V storage was setting
incorrect SRB flags, and Red Hat Enterprise Linux 7 guests running on
Microsoft Hyper-V were experiencing slow I/O as well as I/O failures
when they were connected to a virtual SAN. Now, SRB flags are set
correctly. (BZ#1290095)

* When a NUMA system with no memory in node 0 was used, the system
terminated unexpectedly during boot or when using OpenVSwitch. Now,
the kernel tries to allocate memory from other nodes when node 0 is
not present. (BZ#1300950)

Enhancement :

* IPsec has been updated to provide many fixes and some enhancements.
Of particular note is the ability to match on outgoing interfaces.
(BZ#1287407)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-8104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-0728.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-0774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0103.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/03");
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
  rhsa = "RHSA-2016:0103";
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
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"kernel-abi-whitelists-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-debug-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-debug-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-devel-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-devel-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"kernel-doc-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-headers-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-headers-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-kdump-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-tools-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"perf-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"perf-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"perf-debuginfo-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"python-perf-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"python-perf-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-229.26.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-229.26.2.el7")) flag++;

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
