#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1023. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77046);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2014-0181", "CVE-2014-2672", "CVE-2014-2673", "CVE-2014-2706", "CVE-2014-3534", "CVE-2014-4667");
  script_xref(name:"RHSA", value:"2014:1023");

  script_name(english:"RHEL 7 : kernel (RHSA-2014:1023)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 7.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* It was found that Linux kernel's ptrace subsystem did not properly
sanitize the address-space-control bits when the program-status word
(PSW) was being set. On IBM S/390 systems, a local, unprivileged user
could use this flaw to set address-space-control bits to the kernel
space, and thus gain read and write access to kernel memory.
(CVE-2014-3534, Important)

* It was found that the permission checks performed by the Linux
kernel when a netlink message was received were not sufficient. A
local, unprivileged user could potentially bypass these restrictions
by passing a netlink socket as stdout or stderr to a more privileged
process and altering the output of this process. (CVE-2014-0181,
Moderate)

* It was found that a remote attacker could use a race condition flaw
in the ath_tx_aggr_sleep() function to crash the system by creating
large network traffic on the system's Atheros 9k wireless network
adapter. (CVE-2014-2672, Moderate)

* A flaw was found in the way the Linux kernel performed forking
inside of a transaction. A local, unprivileged user on a PowerPC
system that supports transactional memory could use this flaw to crash
the system. (CVE-2014-2673, Moderate)

* A race condition flaw was found in the way the Linux kernel's
mac80211 subsystem implementation handled synchronization between TX
and STA wake-up code paths. A remote attacker could use this flaw to
crash the system. (CVE-2014-2706, Moderate)

* An integer underflow flaw was found in the way the Linux kernel's
Stream Control Transmission Protocol (SCTP) implementation processed
certain COOKIE_ECHO packets. By sending a specially crafted SCTP
packet, a remote attacker could use this flaw to prevent legitimate
connections to a particular SCTP server socket to be made.
(CVE-2014-4667, Moderate)

Red Hat would like to thank Martin Schwidefsky of IBM for reporting
CVE-2014-3534, Andy Lutomirski for reporting CVE-2014-0181, and Gopal
Reddy Kodudula of Nokia Siemens Networks for reporting CVE-2014-4667.

This update also fixes the following bugs :

* Due to a NULL pointer dereference bug in the IPIP and SIT tunneling
code, a kernel panic could be triggered when using IPIP or SIT tunnels
with IPsec. This update restructures the related code to avoid a NULL
pointer dereference and the kernel no longer panics when using IPIP or
SIT tunnels with IPsec. (BZ#1114957)

* Previously, an IBM POWER8 system could terminate unexpectedly when
the kernel received an IRQ while handling a transactional memory
re-checkpoint critical section. This update ensures that IRQs are
disabled in this situation and the problem no longer occurs.
(BZ#1113150)

* A missing read memory barrier, rmb(), in the bnx2x driver caused the
kernel to crash under various circumstances. This problem has been
fixed by adding an rmb() call to the relevant place in the bnx2x code.
(BZ#1107721)

* The hpwdt driver previously emitted a panic message that was
misleading on certain HP systems. This update ensures that upon a
kernel panic, hpwdt displays information valid on all HP systems.
(BZ#1096961)

* The qla2xxx driver has been upgraded to version 8.06.00.08.07.0-k3,
which provides a number of bug fixes over the previous version in
order to correct various timeout problems with the mailbox commands.
(BZ#1112389)

* The SCSI mid-layer could retry an I/O operation indefinitely if a
storage array repeatedly returned a CHECK CONDITION status to that I/O
operation but the sense data was invalid. This update fixes the
problem by limiting a time for which is such an I/O operation retried.
(BZ#1114468)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0181.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2672.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2673.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2706.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3534.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4667.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1023.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1023";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"kernel-abi-whitelists-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debug-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-devel-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"kernel-doc-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-headers-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-kdump-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"perf-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"perf-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"perf-debuginfo-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-perf-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-perf-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-123.6.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-123.6.3.el7")) flag++;

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
