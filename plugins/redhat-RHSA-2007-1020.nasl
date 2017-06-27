#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1020. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27602);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/29 15:45:04 $");

  script_cve_id("CVE-2007-4351");
  script_osvdb_id(42028);
  script_xref(name:"RHSA", value:"2007:1020");

  script_name(english:"RHEL 5 : cups (RHSA-2007:1020)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated CUPS packages that fix a security issue in the Internet
Printing Protocol (IPP) handling and correct some bugs are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX(R) operating systems.

A flaw was found in the way CUPS handles certain Internet Printing
Protocol (IPP) tags. A remote attacker who is able to connect to the
IPP TCP port could send a malicious request causing the CUPS daemon to
crash, or potentially execute arbitrary code. Please note that the
default CUPS configuration does not allow remote hosts to connect to
the IPP TCP port. (CVE-2007-4351)

Red Hat would like to thank Alin Rad Pop for reporting this issue.

All CUPS users are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue.

In addition, the following bugs were fixed :

* the CUPS service has been changed to start after sshd, to avoid
causing delays when logging in when the system is booted.

* the logrotate settings have been adjusted so they do not cause CUPS
to reload its configuration. This is to avoid re-printing the current
job, which could occur when it was a long-running job.

* a bug has been fixed in the handling of the If-Modified-Since: HTTP
header.

* in the LSPP configuration, labels for labeled jobs did not
line-wrap. This has been fixed.

* an access check in the LSPP configuration has been made more secure.

* the cups-lpd service no longer ignores the '-odocument-format=...'
option.

* a memory allocation bug has been fixed in cupsd.

* support for UNIX domain sockets authentication without passwords has
been added.

* in the LSPP configuration, a problem that could lead to cupsd
crashing has been fixed.

* the error handling in the initscript has been improved.

* The job-originating-host-name attribute was not correctly set for
jobs submitted via the cups-lpd service. This has been fixed.

* a problem with parsing IPv6 addresses in the configuration file has
been fixed.

* a problem that could lead to cupsd crashing when it failed to open a
'file:' URI has been fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4351.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-1020.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2007:1020";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"cups-1.2.4-11.14.el5_1.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"cups-1.2.4-11.14.el5_1.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"cups-1.2.4-11.14.el5_1.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"cups-devel-1.2.4-11.14.el5_1.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"cups-libs-1.2.4-11.14.el5_1.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"cups-lpd-1.2.4-11.14.el5_1.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"cups-lpd-1.2.4-11.14.el5_1.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"cups-lpd-1.2.4-11.14.el5_1.1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs / cups-lpd");
  }
}
