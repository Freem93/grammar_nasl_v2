#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1309. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64002);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/05 14:44:34 $");

  script_cve_id("CVE-2011-1483");
  script_bugtraq_id(49654);
  script_xref(name:"RHSA", value:"2011:1309");
  script_xref(name:"IAVB", value:"2011-B-0119");

  script_name(english:"RHEL 4 / 5 : jbossas (RHSA-2011:1309)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated jbossas packages that fix one security issue are now available
for JBoss Enterprise Application Platform 4.2.0.CP09 for Red Hat
Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

JBoss Enterprise Application Platform is the market-leading platform
for innovative and scalable Java applications. JBoss Enterprise
Application Platform integrates the JBoss Application Server with
JBoss Hibernate and JBoss Seam into a complete and simple enterprise
solution. JBoss Web Services Native is a web service framework
included as part of JBoss Enterprise Application Platform. It
implements the JAX-WS specification.

It was found that JBoss Web Services Native did not properly protect
against recursive entity resolution when processing Document Type
Definitions (DTD). A remote attacker could exploit this flaw by
sending a specially crafted HTTP POST request to a deployed web
service, causing excessive CPU and memory consumption on the system
hosting that service. If the attack is repeated to consume all
available network sockets, the server will become unavailable.
(CVE-2011-1483)

Warning: Before applying this update, please back up your JBoss
Enterprise Application Platform's 'server/[configuration]/deploy/'
directory, along with all other customized configuration files.

Users of JBoss Enterprise Application Platform 4.2.0.CP09 on Red Hat
Enterprise Linux 4 and 5 should upgrade to these updated packages,
which correct this issue. The JBoss server process must be restarted
for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1309.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected jbossas, jbossas-4.2.0.GA_CP09-bin and / or
jbossas-client packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-4.2.0.GA_CP09-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1309";
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
  if (rpm_check(release:"RHEL4", reference:"jbossas-4.2.0-6.GA_CP09.11.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-4.2.0.GA_CP09-bin-4.2.0-6.GA_CP09.11.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-client-4.2.0-6.GA_CP09.11.ep1.el4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"jbossas-4.2.0-6.GA_CP09.11.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-4.2.0.GA_CP09-bin-4.2.0-6.GA_CP09.11.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-client-4.2.0-6.GA_CP09.11.1.ep1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jbossas / jbossas-4.2.0.GA_CP09-bin / jbossas-client");
  }
}
