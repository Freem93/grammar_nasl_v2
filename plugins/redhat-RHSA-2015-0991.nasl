#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0991. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83412);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/06 16:01:51 $");

  script_cve_id("CVE-2014-0227");
  script_bugtraq_id(72717);
  script_osvdb_id(118214);
  script_xref(name:"RHSA", value:"2015:0991");

  script_name(english:"RHEL 6 : tomcat6 (RHSA-2015:0991)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tomcat6 packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

It was discovered that the ChunkedInputFilter in Tomcat did not fail
subsequent attempts to read input after malformed chunked encoding was
detected. A remote attacker could possibly use this flaw to make
Tomcat process part of the request body as new request, or cause a
denial of service. (CVE-2014-0227)

This update also fixes the following bug :

* Before this update, the tomcat6 init script did not try to kill the
tomcat process if an attempt to stop it was unsuccessful, which would
prevent tomcat from restarting properly. The init script was modified
to correct this issue. (BZ#1207048)

All Tomcat 6 users are advised to upgrade to these updated packages,
which correct these issues. Tomcat must be restarted for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0227.html"
  );
  # https://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.43
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0b07cd3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0991.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2015:0991";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat6-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tomcat6-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat6-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat6-admin-webapps-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tomcat6-admin-webapps-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat6-admin-webapps-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat6-debuginfo-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tomcat6-debuginfo-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat6-debuginfo-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat6-docs-webapp-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tomcat6-docs-webapp-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat6-docs-webapp-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat6-el-2.1-api-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tomcat6-el-2.1-api-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat6-el-2.1-api-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat6-javadoc-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tomcat6-javadoc-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat6-javadoc-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat6-jsp-2.1-api-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tomcat6-jsp-2.1-api-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat6-jsp-2.1-api-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat6-lib-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tomcat6-lib-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat6-lib-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat6-servlet-2.5-api-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tomcat6-servlet-2.5-api-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat6-servlet-2.5-api-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat6-webapps-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tomcat6-webapps-6.0.24-83.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat6-webapps-6.0.24-83.el6_6")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat6 / tomcat6-admin-webapps / tomcat6-debuginfo / etc");
  }
}
