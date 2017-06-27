#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2962. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95981);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/10 20:46:33 $");

  script_cve_id("CVE-2016-7117");
  script_osvdb_id(145048);
  script_xref(name:"RHSA", value:"2016:2962");

  script_name(english:"RHEL 5 : kernel (RHSA-2016:2962)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* A use-after-free vulnerability was found in the kernels socket
recvmmsg subsystem. This may allows remote attackers to corrupt memory
and may allow execution of arbitrary code. This corruption takes place
during the error handling routines within __sys_recvmmsg() function.
(CVE-2016-7117, Important)

Bug Fix(es) :

* Previously, guest virtual machines (VMs) on a Hyper-V server cluster
got in some cases rebooted during the graceful node failover test,
because the host kept sending heartbeat packets independently of
guests responding to them. This update fixes the bug by properly
responding to all the heartbeat messages in the queue, even if they
are pending. As a result, guest VMs no longer get rebooted under the
described circumstances. (BZ#1391167)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-7117.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-2962.html"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:2962";
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
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-debuginfo-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-devel-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debuginfo-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debuginfo-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debuginfo-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debuginfo-common-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debuginfo-common-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debuginfo-common-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-devel-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-devel-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-devel-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"kernel-doc-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"kernel-headers-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-headers-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-headers-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-debuginfo-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-debuginfo-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-devel-2.6.18-417.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-417.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-debuginfo / kernel-PAE-devel / etc");
  }
}
