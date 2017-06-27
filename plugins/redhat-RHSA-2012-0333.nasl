#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0333. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76639);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2011-2918", "CVE-2011-4077", "CVE-2011-4097", "CVE-2011-4110", "CVE-2011-4127", "CVE-2011-4131", "CVE-2011-4132", "CVE-2012-0038", "CVE-2012-0044", "CVE-2012-0207", "CVE-2012-0810");
  script_bugtraq_id(49152, 50370, 50459, 50655, 50663, 50755, 51176, 51343, 51371, 51380, 52182);
  script_osvdb_id(74624, 76641, 77092, 77100, 77450, 78014, 78225, 78226, 78227, 79509);
  script_xref(name:"RHSA", value:"2012:0333");

  script_name(english:"RHEL 6 : MRG (RHSA-2012:0333)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel-rt packages that fix multiple security issues and
various bugs are now available for Red Hat Enterprise MRG 2.1.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages contain the Linux kernel.

Security fixes :

* SG_IO ioctl SCSI requests on partitions or LVM volumes could be
passed to the underlying block device, allowing a privileged user to
bypass restrictions and gain read and write access (and be able to
issue other SCSI commands) to the entire block device. (CVE-2011-4127,
Important)

* A local, unprivileged user could use an integer overflow flaw in
drm_mode_dirtyfb_ioctl() to cause a denial of service or escalate
their privileges. (CVE-2012-0044, Important)

* A local, unprivileged user could use a flaw in the Performance
Events implementation to cause a denial of service. (CVE-2011-2918,
Moderate)

* A local, unprivileged user could use flaws in the XFS file system
implementation to cause a denial of service or escalate their
privileges by mounting a specially crafted disk. (CVE-2011-4077,
CVE-2012-0038, Moderate)

* A local, unprivileged user could use a flaw in the Out of Memory
(OOM) killer to monopolize memory, have their process skipped by the
OOM killer, or cause other tasks to be terminated. (CVE-2011-4097,
Moderate)

* A local, unprivileged user could use a flaw in the key management
facility to cause a denial of service. (CVE-2011-4110, Moderate)

* A malicious Network File System version 4 (NFSv4) server could
return a crafted reply to a GETACL request, causing a denial of
service on the client. (CVE-2011-4131, Moderate)

* A local attacker could use a flaw in the Journaling Block Device
(JBD) to crash the system by mounting a specially crafted ext3 or ext4
disk. (CVE-2011-4132, Moderate)

* A flaw in igmp_heard_query() could allow an attacker, who is able to
send certain IGMP (Internet Group Management Protocol) packets to a
target system, to cause a denial of service. (CVE-2012-0207, Moderate)

* If lock contention during signal sending occurred when in a software
interrupt handler that is using the per-CPU debug stack, the task
could be scheduled out on the realtime kernel, possibly leading to
debug stack corruption. A local, unprivileged user could use this flaw
to cause a denial of service. (CVE-2012-0810, Moderate)

Red Hat would like to thank Chen Haogang for reporting CVE-2012-0044;
Wang Xi for reporting CVE-2012-0038; Shubham Goyal for reporting
CVE-2011-4097; Andy Adamson for reporting CVE-2011-4131; and Simon
McVittie for reporting CVE-2012-0207.

Bug fixes :

* When a sleeping task, waiting on a futex (fast userspace mutex),
tried to get the spin_lock(hb->lock) RT-mutex, if the owner of the
futex released the lock, the sleeping task was put on a futex proxy
lock. Consequently, the sleeping task was blocked on two locks and
eventually terminated in the BUG_ON() function. With this update, the
WAKEUP_INPROGRESS pseudo-lock has been added to be used as a proxy
lock. This pseudo-lock tells the sleeping task that it is being woken
up so that the task no longer tries to get the second lock. Now, the
futex code works as expected and sleeping tasks no longer crash in the
described scenario. (BZ#784733)

* When the CONFIG_CRYPTO_FIPS configuration option was disabled, some
services such as sshd and ipsec, while working properly, returned
warning messages regarding this missing option during start up. With
this update, CONFIG_CRYPTO_FIPS has been enabled and no warning
messages are now returned in the described scenario. (BZ#786145)

* Previously, when a read operation on a loop device failed, the data
successfully read from the device was not cleared and could eventually
leak. This bug has been fixed and all data are now properly cleared in
the described scenario. (BZ#761420)

* Due to an assembler-sourced object, the perf utility (from the
perf-rt package) for AMD64 and Intel 64 architectures contained an
executable stack. This update adds the '.note.GNU-stack' section
definition to the bench/mem-memcpy-x86-64-asm.S component of perf,
with all flags disabled, and perf no longer contains an executable
stack, thus fixing this bug. (BZ#783570)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2918.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4097.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4127.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4131.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4132.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0044.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0207.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0810.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0333.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0333";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-devel-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-devel-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-rt-doc-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-rt-firmware-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-devel-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-debuginfo-3.0.18-rt34.53.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-devel-3.0.18-rt34.53.el6rt")) flag++;

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
