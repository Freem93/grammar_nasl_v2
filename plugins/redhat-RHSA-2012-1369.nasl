#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1369. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78937);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:17:29 $");

  script_cve_id("CVE-2012-2679");
  script_bugtraq_id(55934);
  script_osvdb_id(86396);
  script_xref(name:"RHSA", value:"2012:1369");

  script_name(english:"RHEL 5 / 6 : rhncfg (RHSA-2012:1369)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rhncfg packages that fix one security issue, two bugs, and add
one enhancement are now available for Red Hat Network Tools for Red
Hat Enterprise Linux 5 and 6; Red Hat Enterprise Linux 5.3 Long Life;
and Red Hat Enterprise Linux 5.6, 6.0, 6.1, and 6.2 Extended Update
Support.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Red Hat Network Tools provide programs and libraries that allow your
system to use provisioning, monitoring, and configuration management
capabilities provided by Red Hat Network and Red Hat Network
Satellite.

It was discovered that the Red Hat Network (RHN) Configuration Client
(rhncfg-client) tool set world-readable permissions on the '/var/log/
rhncfg-actions' file, used to store the output of different
rhncfg-client actions (such as diffing and verifying files). This
could possibly allow a local attacker to obtain sensitive information
they would otherwise not have access to. (CVE-2012-2679)

Note: With this update, rhncfg-client cannot create diffs of files
that are not already world-readable, and '/var/log/rhncfg-actions' can
only be read and written to by the root user.

This issue was discovered by Paul Wouters of Red Hat.

This update also fixes the following bugs :

* When the user attempted to use the 'rhncfg-client get' command to
download a backup of deployed configuration files and these
configuration files contained a broken symbolic link, the command
failed with an error. This update ensures that 'rhncfg-client get' no
longer fails in this scenario. (BZ#836445)

* The SYNOPSIS section of the rhn-actions-control(8) manual page has
been updated to include the '--report' command line option as
expected. (BZ# 820517)

As well, this update adds the following enhancement :

* The rhncfg-manager utility now supports a new command line option,
'--selinux-context'. This option can be used to upload files and
directories without setting the Security-Enhanced Linux (SELinux)
context. (BZ#770575)

All users of Red Hat Network Tools are advised to upgrade to these
updated packages, which correct these issues and add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:1369.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2679.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhncfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhncfg-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhncfg-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhncfg-management");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1369";
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
  if (rpm_check(release:"RHEL5", reference:"rhncfg-5.10.27-8.el5sat")) flag++;

  if (rpm_check(release:"RHEL5", reference:"rhncfg-actions-5.10.27-8.el5sat")) flag++;

  if (rpm_check(release:"RHEL5", reference:"rhncfg-client-5.10.27-8.el5sat")) flag++;

  if (rpm_check(release:"RHEL5", reference:"rhncfg-management-5.10.27-8.el5sat")) flag++;


  if (rpm_check(release:"RHEL6", reference:"rhncfg-5.10.27-8.el6sat")) flag++;

  if (rpm_check(release:"RHEL6", reference:"rhncfg-actions-5.10.27-8.el6sat")) flag++;

  if (rpm_check(release:"RHEL6", reference:"rhncfg-client-5.10.27-8.el6sat")) flag++;

  if (rpm_check(release:"RHEL6", reference:"rhncfg-management-5.10.27-8.el6sat")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhncfg / rhncfg-actions / rhncfg-client / rhncfg-management");
  }
}
