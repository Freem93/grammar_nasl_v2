#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1998. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80073);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id("CVE-2014-9322");
  script_bugtraq_id(71685);
  script_osvdb_id(115919);
  script_xref(name:"RHSA", value:"2014:1998");

  script_name(english:"RHEL 6 : kernel-rt (RHSA-2014:1998)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated kernel-rt packages that fix one security issue are now
available for Red Hat Enterprise MRG 2.5.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The kernel-rt packages contain the Linux kernel, the core of any Linux
operating system.

  * A flaw was found in the way the Linux kernel handled GS
    segment register base switching when recovering from a
    #SS (stack segment) fault on an erroneous return to user
    space. A local, unprivileged user could use this flaw to
    escalate their privileges on the system. (CVE-2014-9322,
    Important)

Users are advised to upgrade to these updated packages, which upgrade
the kernel-rt kernel to version kernel-rt-3.10.58-rt62.60 and correct
this issue. The system must be rebooted for this update to take
effect.");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-9322.html");
  script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2014-1998.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/17");

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
  rhsa = "RHSA-2014:1998";
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
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-devel-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debuginfo-common-x86_64-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-devel-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-doc-3.10.0-") && rpm_check(release:"RHEL6", reference:"kernel-rt-doc-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-firmware-3.10.0-") && rpm_check(release:"RHEL6", reference:"kernel-rt-firmware-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-devel-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-debuginfo-3.10.58-rt62.60.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-devel-3.10.58-rt62.60.el6rt")) flag++;

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
