#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1116. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60124);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2012-1151");
  script_bugtraq_id(52378);
  script_osvdb_id(79977, 79978);
  script_xref(name:"RHSA", value:"2012:1116");

  script_name(english:"RHEL 5 / 6 : perl-DBD-Pg (RHSA-2012:1116)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated perl-DBD-Pg package that fixes two security issues is now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Perl DBI is a database access Application Programming Interface (API)
for the Perl language. perl-DBD-Pg allows Perl applications to access
PostgreSQL database servers.

Two format string flaws were found in perl-DBD-Pg. A specially crafted
database warning or error message from a server could cause an
application using perl-DBD-Pg to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2012-1151)

All users of perl-DBD-Pg are advised to upgrade to this updated
package, which contains a backported patch to fix these issues.
Applications using perl-DBD-Pg must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1151.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1116.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected perl-DBD-Pg and / or perl-DBD-Pg-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-DBD-Pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-DBD-Pg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/26");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1116";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"perl-DBD-Pg-1.49-4.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"perl-DBD-Pg-1.49-4.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"perl-DBD-Pg-1.49-4.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"perl-DBD-Pg-debuginfo-1.49-4.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"perl-DBD-Pg-debuginfo-1.49-4.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"perl-DBD-Pg-debuginfo-1.49-4.el5_8")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perl-DBD-Pg-2.15.1-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-DBD-Pg-2.15.1-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perl-DBD-Pg-2.15.1-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perl-DBD-Pg-debuginfo-2.15.1-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-DBD-Pg-debuginfo-2.15.1-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perl-DBD-Pg-debuginfo-2.15.1-4.el6_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-DBD-Pg / perl-DBD-Pg-debuginfo");
  }
}
