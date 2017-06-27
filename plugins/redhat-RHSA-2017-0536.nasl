#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0536. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97769);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id("CVE-2016-7545");
  script_osvdb_id(144760);
  script_xref(name:"RHSA", value:"2017:0536");

  script_name(english:"RHEL 7 : policycoreutils (RHSA-2017:0536)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for policycoreutils is now available for Red Hat Enterprise
Linux 7.1 Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The policycoreutils packages contain the core policy utilities
required to manage a SELinux environment.

Security Fix(es) :

* It was found that the sandbox tool provided in policycoreutils was
vulnerable to a TIOCSTI ioctl attack. A specially crafted program
executed via the sandbox command could use this flaw to execute
arbitrary commands in the context of the parent shell, escaping the
sandbox. (CVE-2016-7545)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-7545.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0536.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:U");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils-newrole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils-restorecond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils-sandbox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2017:0536";
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
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"policycoreutils-2.2.5-16.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"policycoreutils-2.2.5-16.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"policycoreutils-debuginfo-2.2.5-16.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"policycoreutils-devel-2.2.5-16.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"policycoreutils-gui-2.2.5-16.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"policycoreutils-gui-2.2.5-16.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"policycoreutils-newrole-2.2.5-16.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"policycoreutils-newrole-2.2.5-16.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"policycoreutils-python-2.2.5-16.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"policycoreutils-python-2.2.5-16.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"policycoreutils-restorecond-2.2.5-16.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"policycoreutils-restorecond-2.2.5-16.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"policycoreutils-sandbox-2.2.5-16.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"policycoreutils-sandbox-2.2.5-16.el7_1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "policycoreutils / policycoreutils-debuginfo / policycoreutils-devel / etc");
  }
}
