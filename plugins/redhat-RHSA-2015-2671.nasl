#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2671. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87519);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2017/01/06 16:11:34 $");

  script_cve_id("CVE-2015-7501");
  script_osvdb_id(130493);
  script_xref(name:"RHSA", value:"2015:2671");

  script_name(english:"RHEL 5 : jakarta-commons-collections (RHSA-2015:2671)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated jakarta-commons-collections packages that fix one security
issue are now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Jakarta/Apache Commons Collections library provides new
interfaces, implementations, and utilities to extend the features of
the Java Collections Framework.

It was found that the Apache commons-collections library permitted
code execution when deserializing objects involving a specially
constructed chain of classes. A remote attacker could use this flaw to
execute arbitrary code with the permissions of the application using
the commons-collections library. (CVE-2015-7501)

With this update, deserialization of certain classes in the
commons-collections library is no longer allowed. Applications that
require those classes to be deserialized can use the system property
'org.apache.commons.collections.enableUnsafeSerialization' to
re-enable their deserialization.

Further information about this security flaw may be found at:
https://access.redhat.com/solutions/2045023

All users of jakarta-commons-collections are advised to upgrade to
these updated packages, which contain a backported patch to correct
this issue. All running applications using the commons-collections
library must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7501.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/solutions/2045023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2671.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections-testframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections-testframework-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections-tomcat5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/21");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2671";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jakarta-commons-collections-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"jakarta-commons-collections-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jakarta-commons-collections-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jakarta-commons-collections-debuginfo-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"jakarta-commons-collections-debuginfo-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jakarta-commons-collections-debuginfo-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jakarta-commons-collections-javadoc-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"jakarta-commons-collections-javadoc-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jakarta-commons-collections-javadoc-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jakarta-commons-collections-testframework-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"jakarta-commons-collections-testframework-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jakarta-commons-collections-testframework-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jakarta-commons-collections-testframework-javadoc-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"jakarta-commons-collections-testframework-javadoc-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jakarta-commons-collections-testframework-javadoc-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jakarta-commons-collections-tomcat5-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"jakarta-commons-collections-tomcat5-3.2-2jpp.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jakarta-commons-collections-tomcat5-3.2-2jpp.4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jakarta-commons-collections / jakarta-commons-collections-debuginfo / etc");
  }
}
