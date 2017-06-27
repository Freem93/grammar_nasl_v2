#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0285. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81625);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2014-7841");
  script_osvdb_id(114575);
  script_xref(name:"RHSA", value:"2015:0285");

  script_name(english:"RHEL 6 : kernel (RHSA-2015:0285)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and three bugs are
now available for Red Hat Enterprise Linux 6.4 Extended Update
Support.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way the Linux kernel's SCTP implementation
validated INIT chunks when performing Address Configuration Change
(ASCONF). A remote attacker could use this flaw to crash the system by
sending a specially crafted SCTP packet to trigger a NULL pointer
dereference on the system. (CVE-2014-7841, Important)

This issue was discovered by Liu Wei of Red Hat.

This update also fixes the following bugs :

* Due to several bugs in the network console logging, a race condition
between the network console send operation and the driver's IRQ
handler could occur, or the network console could access invalid
memory content. As a consequence, the respective driver, such as
vmxnet3, triggered a BUG_ON() assertion and the system terminated
unexpectedly. A patch addressing these bugs has been applied so that
driver's IRQs are disabled before processing the send operation and
the network console now accesses the RCU-protected (read-copy update)
data properly. Systems using the network console logging no longer
crashes due to the aforementioned conditions. (BZ#1165983)

* A bug in the vmxnet3 driver allowed potential race conditions to be
triggered when the driver was used with the netconsole module. The
race conditions allowed the driver's internal New API (NAPI) poll
routine to run concurrently with the netpoll controller routine, which
resulted in data corruption and a subsequent kernel panic. To fix this
problem, the vmxnet3 driver has been modified to call the appropriate
interrupt handler to schedule NAPI poll requests properly.
(BZ#1179594)

* Prior to this update, nfs_mark_return_delegation() was called
without any locking, resulting in unsafe dereferencing of
delegation->inode. Because the inode is only used to discover the
nfs_client, the callers now pass a valid pointer to the nfs_server as
a parameter. (BZ#1187637)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0285.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6\.4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.4", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0285";
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
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"kernel-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debug-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debug-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"kernel-debug-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debug-devel-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debuginfo-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-devel-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-devel-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"kernel-devel-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", reference:"kernel-doc-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", reference:"kernel-firmware-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-headers-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-headers-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"kernel-headers-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-kdump-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"perf-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"perf-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"perf-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"perf-debuginfo-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"perf-debuginfo-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"python-perf-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"python-perf-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"python-perf-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-358.56.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-358.56.1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-debuginfo / kernel-debug-devel / etc");
  }
}
