#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0953. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55616);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2011-2520");
  script_bugtraq_id(48715);
  script_osvdb_id(73976);
  script_xref(name:"RHSA", value:"2011:0953");

  script_name(english:"RHEL 6 : system-config-firewall (RHSA-2011:0953)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated system-config-firewall packages that fix one security issue
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

system-config-firewall is a graphical user interface for basic
firewall setup.

It was found that system-config-firewall used the Python pickle module
in an insecure way when sending data (via D-Bus) to the privileged
back-end mechanism. A local user authorized to configure firewall
rules using system-config-firewall could use this flaw to execute
arbitrary code with root privileges, by sending a specially crafted
serialized object. (CVE-2011-2520)

Red Hat would like to thank Marco Slaviero of SensePost for reporting
this issue.

This erratum updates system-config-firewall to use JSON (JavaScript
Object Notation) for data exchange, instead of pickle. Therefore, an
updated version of system-config-printer that uses this new
communication data format is also provided in this erratum.

Users of system-config-firewall are advised to upgrade to these
updated packages, which contain a backported patch to resolve this
issue. Running instances of system-config-firewall must be restarted
before the utility will be able to communicate with its updated
back-end."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2520.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0953.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:system-config-firewall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:system-config-firewall-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:system-config-firewall-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:system-config-printer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:system-config-printer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:system-config-printer-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:system-config-printer-udev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/19");
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
  rhsa = "RHSA-2011:0953";
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
  if (rpm_check(release:"RHEL6", reference:"system-config-firewall-1.2.27-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"system-config-firewall-base-1.2.27-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"system-config-firewall-tui-1.2.27-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"system-config-printer-1.1.16-17.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"system-config-printer-1.1.16-17.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"system-config-printer-1.1.16-17.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"system-config-printer-debuginfo-1.1.16-17.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"system-config-printer-debuginfo-1.1.16-17.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"system-config-printer-debuginfo-1.1.16-17.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"system-config-printer-libs-1.1.16-17.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"system-config-printer-libs-1.1.16-17.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"system-config-printer-libs-1.1.16-17.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"system-config-printer-udev-1.1.16-17.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"system-config-printer-udev-1.1.16-17.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"system-config-printer-udev-1.1.16-17.el6_1.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "system-config-firewall / system-config-firewall-base / etc");
  }
}
