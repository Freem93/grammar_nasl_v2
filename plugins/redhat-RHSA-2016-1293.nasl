#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1293. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91803);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/10 20:34:13 $");

  script_cve_id("CVE-2016-4444", "CVE-2016-4446", "CVE-2016-4989");
  script_osvdb_id(140303, 140304, 140305, 140307);
  script_xref(name:"RHSA", value:"2016:1293");

  script_name(english:"RHEL 7 : setroubleshoot and setroubleshoot-plugins (RHSA-2016:1293)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for setroubleshoot and setroubleshoot-plugins is now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The setroubleshoot packages provide tools to help diagnose SELinux
problems. When Access Vector Cache (AVC) messages are returned, an
alert can be generated that provides information about the problem and
helps to track its resolution.

The setroubleshoot-plugins package provides a set of analysis plugins
for use with setroubleshoot. Each plugin has the capacity to analyze
SELinux AVC data and system data to provide user friendly reports
describing how to interpret SELinux AVC denials.

Security Fix(es) :

* Shell command injection flaws were found in the way the
setroubleshoot executed external commands. A local attacker able to
trigger certain SELinux denials could use these flaws to execute
arbitrary code with privileges of the setroubleshoot user.
(CVE-2016-4989)

* Shell command injection flaws were found in the way the
setroubleshoot allow_execmod and allow_execstack plugins executed
external commands. A local attacker able to trigger an execmod or
execstack SELinux denial could use these flaws to execute arbitrary
code with privileges of the setroubleshoot user. (CVE-2016-4444,
CVE-2016-4446)

The CVE-2016-4444 and CVE-2016-4446 issues were discovered by Milos
Malik (Red Hat) and the CVE-2016-4989 issue was discovered by Red Hat
Product Security.

Note: On Red Hat Enterprise Linux 7.0 and 7.1, the setroubleshoot is
run with root privileges. Therefore, these issues could allow an
attacker to execute arbitrary code with root privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-4444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-4446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-4989.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-1293.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:setroubleshoot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:setroubleshoot-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:setroubleshoot-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:setroubleshoot-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1293";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"setroubleshoot-3.2.24-4.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"setroubleshoot-3.2.24-4.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"setroubleshoot-debuginfo-3.2.24-4.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"setroubleshoot-debuginfo-3.2.24-4.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"setroubleshoot-plugins-3.0.59-2.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"setroubleshoot-server-3.2.24-4.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"setroubleshoot-server-3.2.24-4.el7_2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "setroubleshoot / setroubleshoot-debuginfo / setroubleshoot-plugins / etc");
  }
}
