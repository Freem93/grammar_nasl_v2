#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1088. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55684);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2011-2502", "CVE-2011-2503");
  script_xref(name:"RHSA", value:"2011:1088");

  script_name(english:"RHEL 6 : systemtap (RHSA-2011:1088)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated systemtap packages that fix two security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

SystemTap is an instrumentation system for systems running the Linux
kernel. The system allows developers to write scripts to collect data
on the operation of the system.

It was found that SystemTap did not perform proper module path sanity
checking if a user specified a custom path to the uprobes module, used
when performing user-space probing ('staprun -u'). A local user who is
a member of the stapusr group could use this flaw to bypass intended
module-loading restrictions, allowing them to escalate their
privileges by loading an arbitrary, unsigned module. (CVE-2011-2502)

A race condition flaw was found in the way the staprun utility
performed module loading. A local user who is a member of the stapusr
group could use this flaw to modify a signed module while it is being
loaded, allowing them to escalate their privileges. (CVE-2011-2503)

SystemTap users should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2502.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2503.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1088.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-grapher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-initscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-sdt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2011:1088";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"systemtap-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"systemtap-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"systemtap-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"systemtap-client-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"systemtap-client-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"systemtap-client-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"systemtap-debuginfo-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"systemtap-grapher-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"systemtap-grapher-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"systemtap-grapher-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"systemtap-initscript-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"systemtap-initscript-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"systemtap-initscript-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"systemtap-runtime-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"systemtap-runtime-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"systemtap-runtime-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"systemtap-sdt-devel-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"systemtap-server-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"systemtap-server-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"systemtap-server-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"systemtap-testsuite-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"systemtap-testsuite-1.4-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"systemtap-testsuite-1.4-6.el6_1.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemtap / systemtap-client / systemtap-debuginfo / etc");
  }
}
