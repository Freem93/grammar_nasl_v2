#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1171. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76663);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2013-4255");
  script_osvdb_id(96965);
  script_xref(name:"RHSA", value:"2013:1171");

  script_name(english:"RHEL 5 : MRG (RHSA-2013:1171)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated condor packages that fix one security issue are now available
for Red Hat Enterprise MRG 2.3 for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

HTCondor is a specialized workload management system for
compute-intensive jobs. It provides a job queuing mechanism,
scheduling policy, priority scheme, and resource monitoring and
management.

A denial of service flaw was found in the way HTCondor's policy
definition evaluator processed certain policy definitions. If an
administrator used an attribute defined on a job in a CONTINUE, KILL,
PREEMPT, or SUSPEND condor_startd policy, a remote HTCondor service
user could use this flaw to cause condor_startd to exit by submitting
a job that caused such a policy definition to be evaluated to either
the ERROR or UNDEFINED states. (CVE-2013-4255)

Note: This issue did not affect the default HTCondor configuration.

This issue was found by Matthew Farrellee of Red Hat.

All Red Hat Enterprise MRG 2.3 users are advised to upgrade to these
updated packages, which contain a backported patch to correct this
issue. HTCondor must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4255.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1171.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-aviary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-classads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-kbdd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-vm-gahp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/21");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1171";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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

  if (! (rpm_exists(release:"RHEL5", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-7.8.8-0.4.2.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-7.8.8-0.4.2.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-aviary-7.8.8-0.4.2.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-aviary-7.8.8-0.4.2.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-classads-7.8.8-0.4.2.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-classads-7.8.8-0.4.2.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-kbdd-7.8.8-0.4.2.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-kbdd-7.8.8-0.4.2.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-qmf-7.8.8-0.4.2.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-qmf-7.8.8-0.4.2.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-vm-gahp-7.8.8-0.4.2.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-vm-gahp-7.8.8-0.4.2.el5_9")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "condor / condor-aviary / condor-classads / condor-kbdd / condor-qmf / etc");
  }
}
