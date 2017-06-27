#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0920. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55520);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2011-1526");
  script_osvdb_id(73617);
  script_xref(name:"RHSA", value:"2011:0920");

  script_name(english:"RHEL 6 : krb5-appl (RHSA-2011:0920)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5-appl packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The krb5-appl packages provide Kerberos-aware telnet, ftp, rcp, rsh,
and rlogin clients and servers. While these have been replaced by
tools such as OpenSSH in most environments, they remain in use in
others.

It was found that gssftp, a Kerberos-aware FTP server, did not
properly drop privileges. A remote FTP user could use this flaw to
gain unauthorized read or write access to files that are owned by the
root group. (CVE-2011-1526)

Red Hat would like to thank the MIT Kerberos project for reporting
this issue. Upstream acknowledges Tim Zingelman as the original
reporter.

All krb5-appl users should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1526.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2011-005.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0920.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected krb5-appl-clients, krb5-appl-debuginfo and / or
krb5-appl-servers packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-appl-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-appl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-appl-servers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/06");
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
  rhsa = "RHSA-2011:0920";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"krb5-appl-clients-1.0.1-2.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"krb5-appl-clients-1.0.1-2.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"krb5-appl-clients-1.0.1-2.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"krb5-appl-debuginfo-1.0.1-2.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"krb5-appl-debuginfo-1.0.1-2.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"krb5-appl-debuginfo-1.0.1-2.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"krb5-appl-servers-1.0.1-2.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"krb5-appl-servers-1.0.1-2.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"krb5-appl-servers-1.0.1-2.el6_1.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-appl-clients / krb5-appl-debuginfo / krb5-appl-servers");
  }
}
