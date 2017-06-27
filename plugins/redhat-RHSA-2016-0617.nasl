#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0617. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90494);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/01/10 20:34:12 $");

  script_cve_id("CVE-2016-0774");
  script_osvdb_id(122968);
  script_xref(name:"RHSA", value:"2016:0617");

  script_name(english:"RHEL 6 : kernel (RHSA-2016:0617)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 6.6
Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* It was found that the fix for CVE-2015-1805 incorrectly kept buffer
offset and buffer length in sync on a failed atomic read, potentially
resulting in a pipe buffer state corruption. A local, unprivileged
user could use this flaw to crash the system or leak kernel memory to
user space. (CVE-2016-0774, Moderate)

The security impact of this issue was discovered by Red Hat.

Bug Fix(es) :

* Due to prematurely decremented calc_load_task, the calculated load
average was off by up to the number of CPUs in the machine. As a
consequence, job scheduling worked improperly causing a drop in the
system performance. This update keeps the delta of the CPU going into
NO_HZ idle separately, and folds the pending idle delta into the
global active count while correctly aging the averages for the
idle-duration when leaving NO_HZ mode. Now, job scheduling works
correctly, ensuring balanced CPU load. (BZ#1308968)

* Previously, the Stream Control Transmission Protocol (SCTP)
retransmission path selection was not fully RFC compliant when Partial
Failover had been enabled. The provided patch provides SCTP path
selection updates, thus fixing this bug. (BZ#1306565)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-0774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0617.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");
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
if (! ereg(pattern:"^6\.6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.6", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0617";
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
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"kernel-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"kernel-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"kernel-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"kernel-abi-whitelists-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"kernel-debug-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"kernel-debug-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"kernel-debug-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"kernel-debug-devel-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"kernel-debuginfo-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"kernel-devel-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"kernel-devel-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"kernel-devel-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"kernel-doc-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"kernel-firmware-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"kernel-headers-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"kernel-headers-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"kernel-headers-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"kernel-kdump-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"perf-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"perf-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"perf-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"perf-debuginfo-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"perf-debuginfo-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"python-perf-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"python-perf-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"python-perf-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-504.46.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-504.46.1.el6")) flag++;

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