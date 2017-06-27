#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1059. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64046);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2011-5245", "CVE-2012-0818");
  script_bugtraq_id(51748);
  script_osvdb_id(78679, 78680);
  script_xref(name:"RHSA", value:"2012:1059");

  script_name(english:"RHEL 4 / 5 / 6 : resteasy (RHSA-2012:1059)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated resteasy packages that fix one security issue are now
available for JBoss Enterprise Application Platform 5.1.2 for Red Hat
Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

RESTEasy provides various frameworks to help you build RESTful web
services and RESTful Java applications.

It was found that RESTEasy was vulnerable to XML External Entity (XXE)
attacks. If a remote attacker submitted a request containing an
external XML entity to a RESTEasy endpoint, the entity would be
resolved, allowing the attacker to read files accessible to the user
running the application server. This flaw affected DOM (Document
Object Model) Document and JAXB (Java Architecture for XML Binding)
input. (CVE-2012-0818)

Note: The fix for CVE-2012-0818 is not enabled by default. This update
adds a new configuration option to disable entity expansion in
RESTEasy. If applications on your server expose RESTEasy XML
endpoints, a resteasy.document.expand.entity.references configuration
snippet must be added to their web.xml file to disable entity
expansion in RESTEasy. Refer to Red Hat Bugzilla bug 785631 for
details.

Warning: Before applying this update, back up your JBoss Enterprise
Application Platform's 'jboss-as/server/[PROFILE]/deploy/' directory,
along with all other customized configuration files.

Users of JBoss Enterprise Application Platform 5.1.2 on Red Hat
Enterprise Linux 4, 5, and 6 should upgrade to these updated packages,
which correct this issue. The JBoss server process must be restarted
for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-5245.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0818.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=785631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1059.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1059";
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
  if (rpm_check(release:"RHEL4", reference:"resteasy-1.2.1-10.CP02_patch01.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"resteasy-examples-1.2.1-10.CP02_patch01.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"resteasy-javadoc-1.2.1-10.CP02_patch01.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"resteasy-manual-1.2.1-10.CP02_patch01.1.ep5.el4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"resteasy-1.2.1-10.CP02_patch01.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"resteasy-examples-1.2.1-10.CP02_patch01.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"resteasy-javadoc-1.2.1-10.CP02_patch01.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"resteasy-manual-1.2.1-10.CP02_patch01.1.ep5.el5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"resteasy-1.2.1-10.CP02_patch01.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-examples-1.2.1-10.CP02_patch01.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-javadoc-1.2.1-10.CP02_patch01.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-manual-1.2.1-10.CP02_patch01.1.ep5.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "resteasy / resteasy-examples / resteasy-javadoc / resteasy-manual");
  }
}
