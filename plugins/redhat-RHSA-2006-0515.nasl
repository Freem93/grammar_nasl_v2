#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0515. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21721);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/29 15:35:19 $");

  script_cve_id("CVE-2006-1173");
  script_osvdb_id(26197);
  script_xref(name:"CERT", value:"146718");
  script_xref(name:"RHSA", value:"2006:0515");

  script_name(english:"RHEL 2.1 / 3 / 4 : sendmail (RHSA-2006:0515)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sendmail packages are now available to fix a denial of service
security issue.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

[Updated 27 June 2006] The sendmail-docs packages for Red Hat
Enterprise Linux 3 have been updated to the correct version and
release.

Sendmail is a Mail Transport Agent (MTA) used to send mail between
machines.

A flaw in the handling of multi-part MIME messages was discovered in
Sendmail. A remote attacker could create a carefully crafted message
that could crash the sendmail process during delivery (CVE-2006-1173).
By default on Red Hat Enterprise Linux, Sendmail is configured to only
accept connections from the local host. Therefore, only users who have
configured Sendmail to listen to remote hosts would be remotely
vulnerable to this issue.

Users of Sendmail are advised to upgrade to these erratum packages,
which contain a backported patch from the Sendmail team to correct
this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1173.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2006-0515.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sendmail-cf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sendmail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sendmail-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0515";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"sendmail-8.12.11-4.21AS.10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"sendmail-cf-8.12.11-4.21AS.10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"sendmail-devel-8.12.11-4.21AS.10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"sendmail-doc-8.12.11-4.21AS.10")) flag++;

  if (rpm_check(release:"RHEL3", reference:"sendmail-8.12.11-4.RHEL3.6")) flag++;
  if (rpm_check(release:"RHEL3", reference:"sendmail-cf-8.12.11-4.RHEL3.6")) flag++;
  if (rpm_check(release:"RHEL3", reference:"sendmail-devel-8.12.11-4.RHEL3.6")) flag++;
  if (rpm_check(release:"RHEL3", reference:"sendmail-doc-8.12.11-4.RHEL3.6")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sendmail-8.13.1-3.RHEL4.5")) flag++;
  if (rpm_check(release:"RHEL4", reference:"sendmail-cf-8.13.1-3.RHEL4.5")) flag++;
  if (rpm_check(release:"RHEL4", reference:"sendmail-devel-8.13.1-3.RHEL4.5")) flag++;
  if (rpm_check(release:"RHEL4", reference:"sendmail-doc-8.13.1-3.RHEL4.5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sendmail / sendmail-cf / sendmail-devel / sendmail-doc");
  }
}
