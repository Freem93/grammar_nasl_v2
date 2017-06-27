#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0913. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76696);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id(
    "CVE-2014-0181",
    "CVE-2014-0206",
    "CVE-2014-3144",
    "CVE-2014-3145",
    "CVE-2014-3153",
    "CVE-2014-3917",
    "CVE-2014-3940",
    "CVE-2014-4027",
    "CVE-2014-4667",
    "CVE-2014-4699"
  );
  script_bugtraq_id(
    67034,
    67309,
    67321,
    67699,
    67786,
    67906,
    67985,
    68176,
    68224,
    68411
  );
  script_osvdb_id(
    106174,
    106871,
    106969,
    107531,
    107650,
    107752,
    108001,
    108392,
    108473,
    108754
  );
  script_xref(name:"RHSA", value:"2014:0913");
  script_xref(name:"EDB-ID", value:"35370");
  script_xref(name:"EDB-ID", value:"34134");

  script_name(english:"RHEL 6 : kernel-rt (RHSA-2014:0913)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated kernel-rt packages that fix multiple security issues are now
available for Red Hat Enterprise MRG 2.5.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel-rt packages contain the Linux kernel, the core of any Linux
operating system.

  * A flaw was found in the way the Linux kernel's futex
    subsystem handled the requeuing of certain Priority
    Inheritance (PI) futexes. A local, unprivileged user
    could use this flaw to escalate their privileges on the
    system. (CVE-2014-3153, Important)

  * It was found that the Linux kernel's ptrace subsystem
    allowed a traced process' instruction pointer to be set
    to a non-canonical memory address without forcing the
    non-sysret code path when returning to user space. A
    local, unprivileged user could use this flaw to crash
    the system or, potentially, escalate their privileges
    on the system. Note that this issue only affected
    systems using an Intel CPU. (CVE-2014-4699, Important)

  * It was found that the permission checks performed by the
    Linux kernel when a netlink message was received were
    not sufficient. A local, unprivileged user could
    potentially bypass these restrictions by passing a
    netlink socket as stdout or stderr to a more privileged
    process and altering the output of this process.
    (CVE-2014-0181, Moderate)

  * It was found that the aio_read_events_ring() function
    of the Linux kernel's Asynchronous I/O (AIO) subsystem
    did not properly sanitize the AIO ring head received
    from user space. A local, unprivileged user could use
    this flaw to disclose random parts of the (physical)
    memory belonging to the kernel and/or other processes.
    (CVE-2014-0206, Moderate)

  * An out-of-bounds memory access flaw was found in the
    Netlink Attribute extension of the Berkeley Packet
    Filter (BPF) interpreter functionality in the Linux
    kernel's networking implementation. A local,
    unprivileged user could use this flaw to crash the
    system or leak kernel memory to user space via a
    specially crafted socket filter. (CVE-2014-3144,
    CVE-2014-3145, Moderate)

  * An out-of-bounds memory access flaw was found in the
    Linux kernel's system call auditing implementation. On
    a system with existing audit rules defined, a local,
    unprivileged user could use this flaw to leak kernel
    memory to user space or, potentially, crash the system.
    (CVE-2014-3917, Moderate)

  * A flaw was found in the way Linux kernel's Transparent
    Huge Pages (THP) implementation handled non-huge page
    migration. A local, unprivileged user could use this
    flaw to crash the kernel by migrating transparent
    hugepages. (CVE-2014-3940, Moderate)

  * An integer underflow flaw was found in the way the Linux
    kernel's Stream Control Transmission Protocol (SCTP)
    implementation processed certain COOKIE_ECHO packets.
    By sending a specially crafted SCTP packet, a remote
    attacker could use this flaw to prevent legitimate
    connections to a particular SCTP server socket to be
    made. (CVE-2014-4667, Moderate)

  * An information leak flaw was found in the RAM Disks
    Memory Copy (rd_mcp) back-end driver of the iSCSI Target
    subsystem of the Linux kernel. A privileged user could
    use this flaw to leak the contents of kernel memory to
    an iSCSI initiator remote client. (CVE-2014-4027, Low)

Users are advised to upgrade to these updated packages, which upgrade
the kernel-rt kernel to version kernel-rt-3.10.33-rt32.43 and correct
these issues. The system must be rebooted for this update to take
effect.");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-0181.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-0206.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-3144.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-3145.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-3153.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-3917.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-3940.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-4027.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-4667.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-4699.html");
  script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2014-0913.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android \'Towelroot\' Futex Requeue Kernel Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0913";
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
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-devel-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debuginfo-common-x86_64-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-devel-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-doc-3.10.0-") && rpm_check(release:"RHEL6", reference:"kernel-rt-doc-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-firmware-3.10.0-") && rpm_check(release:"RHEL6", reference:"kernel-rt-firmware-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-devel-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-debuginfo-3.10.33-rt32.43.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-devel-3.10.33-rt32.43.el6rt")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt / kernel-rt-debug / kernel-rt-debug-debuginfo / etc");
  }
}
