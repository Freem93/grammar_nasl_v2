#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2675. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94651);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/10 20:46:33 $");

  script_cve_id("CVE-2016-7035");
  script_osvdb_id(146618);
  script_xref(name:"RHSA", value:"2016:2675");

  script_name(english:"RHEL 6 : pacemaker (RHSA-2016:2675)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for pacemaker is now available for Red Hat Enterprise Linux
6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Pacemaker cluster resource manager is a collection of technologies
working together to provide data integrity and the ability to maintain
application availability in the event of a failure.

Security Fix(es) :

* An authorization flaw was found in Pacemaker, where it did not
properly guard its IPC interface. An attacker with an unprivileged
account on a Pacemaker node could use this flaw to, for example, force
the Local Resource Manager daemon to execute a script as root and
thereby gain root access on the machine. (CVE-2016-7035)

This issue was discovered by Jan 'poki' Pokorny (Red Hat) and Alain
Moulle (ATOS/BULL)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-7035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-2675.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cluster-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/09");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:2675";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-cli-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-cli-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-cluster-libs-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-cluster-libs-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-cts-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-cts-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-debuginfo-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-debuginfo-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-doc-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-doc-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-libs-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-libs-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-libs-devel-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-libs-devel-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-remote-1.1.14-8.el6_8.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-remote-1.1.14-8.el6_8.2")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pacemaker / pacemaker-cli / pacemaker-cluster-libs / pacemaker-cts / etc");
  }
}
