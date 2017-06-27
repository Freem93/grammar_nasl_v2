#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0874. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59591);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2012-2102");
  script_bugtraq_id(52931);
  script_osvdb_id(81059);
  script_xref(name:"RHSA", value:"2012:0874");

  script_name(english:"RHEL 6 : mysql (RHSA-2012:0874)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix one security issue and add one
enhancement are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

A flaw was found in the way MySQL processed HANDLER READ NEXT
statements after deleting a record. A remote, authenticated attacker
could use this flaw to provide such requests, causing mysqld to crash.
This issue only caused a temporary denial of service, as mysqld was
automatically restarted after the crash. (CVE-2012-2102)

This update also adds the following enhancement :

* The InnoDB storage engine is built-in for all architectures. This
update adds InnoDB Plugin, the InnoDB storage engine as a plug-in for
the 32-bit x86, AMD64, and Intel 64 architectures. The plug-in offers
additional features and better performance than when using the
built-in InnoDB storage engine. Refer to the MySQL documentation,
linked to in the References section, for information about enabling
the plug-in. (BZ#740224)

All MySQL users should upgrade to these updated packages, which add
this enhancement and contain a backported patch to correct this issue.
After installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2102.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/replacing-builtin-innodb.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0874.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/20");
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
  rhsa = "RHSA-2012:0874";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mysql-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mysql-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mysql-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mysql-bench-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mysql-bench-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mysql-bench-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mysql-debuginfo-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mysql-devel-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mysql-embedded-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mysql-embedded-devel-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mysql-libs-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mysql-server-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mysql-server-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mysql-server-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mysql-test-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mysql-test-5.1.61-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mysql-test-5.1.61-4.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-debuginfo / mysql-devel / etc");
  }
}
