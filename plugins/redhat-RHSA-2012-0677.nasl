#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0677. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59222);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2012-0866", "CVE-2012-0868");
  script_bugtraq_id(52188);
  script_osvdb_id(79644, 79646);
  script_xref(name:"RHSA", value:"2012:0677");

  script_name(english:"RHEL 5 : postgresql (RHSA-2012:0677)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix two security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

The pg_dump utility inserted object names literally into comments in
the SQL script it produces. An unprivileged database user could create
an object whose name includes a newline followed by a SQL command.
This SQL command might then be executed by a privileged user during
later restore of the backup dump, allowing privilege escalation.
(CVE-2012-0868)

CREATE TRIGGER did not do a permissions check on the trigger function
to be called. This could possibly allow an authenticated database user
to call a privileged trigger function on data of their choosing.
(CVE-2012-0866)

All PostgreSQL users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. If the
postgresql service is running, it will be automatically restarted
after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0866.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0868.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0677.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/22");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0677";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-contrib-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-contrib-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-contrib-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", reference:"postgresql-debuginfo-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", reference:"postgresql-devel-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-docs-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-docs-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-docs-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", reference:"postgresql-libs-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-pl-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-pl-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-pl-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-python-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-python-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-python-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-server-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-server-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-server-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-tcl-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-tcl-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-tcl-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-test-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-test-8.1.23-4.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-test-8.1.23-4.el5_8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-debuginfo / etc");
  }
}
