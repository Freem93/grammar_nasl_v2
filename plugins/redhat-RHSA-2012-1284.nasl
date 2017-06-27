#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1284. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62170);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:17:29 $");

  script_cve_id("CVE-2012-4425");
  script_bugtraq_id(55555);
  script_osvdb_id(85551);
  script_xref(name:"RHSA", value:"2012:1284");

  script_name(english:"RHEL 6 : spice-gtk (RHSA-2012:1284)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated spice-gtk packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for SPICE
(Simple Protocol for Independent Computing Environments) clients. Both
Virtual Machine Manager and Virtual Machine Viewer can make use of
this widget to access virtual machines using the SPICE protocol.

It was discovered that the spice-gtk setuid helper application,
spice-client-glib-usb-acl-helper, did not clear the environment
variables read by the libraries it uses. A local attacker could
possibly use this flaw to escalate their privileges by setting
specific environment variables before running the helper application.
(CVE-2012-4425)

Red Hat would like to thank Sebastian Krahmer of the SUSE Security
Team for reporting this issue.

All users of spice-gtk are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4425.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1284.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-gtk-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-gtk-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:1284";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-glib-0.11-11.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-glib-0.11-11.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-glib-devel-0.11-11.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-glib-devel-0.11-11.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-gtk-0.11-11.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-gtk-0.11-11.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-gtk-debuginfo-0.11-11.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-gtk-debuginfo-0.11-11.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-gtk-devel-0.11-11.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-gtk-devel-0.11-11.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-gtk-python-0.11-11.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-gtk-python-0.11-11.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-gtk-tools-0.11-11.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-gtk-tools-0.11-11.el6_3.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spice-glib / spice-glib-devel / spice-gtk / spice-gtk-debuginfo / etc");
  }
}
