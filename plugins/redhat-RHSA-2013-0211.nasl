#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0211. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78948);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2012-6115", "CVE-2013-0168");
  script_bugtraq_id(57749, 57750);
  script_osvdb_id(91264, 91266);
  script_xref(name:"RHSA", value:"2013:0211");

  script_name(english:"RHEL 6 : rhevm 3.1.2 (RHSA-2013:0211)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rhevm packages that fix two security issues and various bugs
are now available.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Red Hat Enterprise Virtualization Manager is a centralized
management platform that allows system administrators to view and
manage virtual machines. The Red Hat Enterprise Virtualization Manager
provides a comprehensive range of features including search
capabilities, resource management, live migrations, and virtual
infrastructure provisioning. The Manager is a JBoss Application Server
application that provides several interfaces through which the virtual
environment can be accessed and interacted with, including an
Administration Portal, a User Portal, and a Representational State
Transfer (REST) Application Programming Interface (API).

It was discovered that running the domain management tool with the
validate action ('rhevm-manage-domains -action=validate') logged
administrative passwords to a world-readable log file. A local
attacker could use this flaw to gain control of systems that are
managed by Red Hat Enterprise Virtualization Manager. (CVE-2012-6115)

A flaw was found in the way the MoveDisk command checked permissions
on the target storage domain. A privileged user (a storage admin of a
storage domain) could use this flaw to exhaust all available free
space in another storage domain they would otherwise not have access
to. (CVE-2013-0168)

The CVE-2012-6115 issue was discovered by Andrew Cathrow of Red Hat.
The CVE-2013-0168 issue was discovered by Ondrej Machacek of Red Hat.

Previously, upgrading from Red Hat Enterprise Virtualization Manager
3.0 to 3.1 was not formally supported by Red Hat. This update fixes a
number of known issues with the upgrade process. As a result,
upgrading from Red Hat Enterprise Virtualization Manager 3.0 to 3.1 is
now supported.

For more information on upgrading to Red Hat Enterprise Virtualization
Manager 3.1, consult the Installation Guide :

https://access.redhat.com/knowledge/docs/en-US/
Red_Hat_Enterprise_Virtualization/3.1/html/Installation_Guide/
chap-Upgrading_to_Red_Hat_Enterprise_Virtualization_3.1.html

Additional tips and considerations to take into account are also
available in the Red Hat Knowledgebase :

https://access.redhat.com/knowledge/articles/269333

Information on the bugs fixed in this update is available in the
Technical Notes document :

https://access.redhat.com/knowledge/docs/en-US/
Red_Hat_Enterprise_Virtualization/3.1/html/Technical_Notes/
chap-RHSA-2013-0211.html

All Red Hat Enterprise Virtualization Manager administrators are
advised to install these updated packages, which fix these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6115.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0168.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/knowledge/docs/en-US/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/knowledge/articles/269333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0211.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-genericapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-notification-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-allinone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-userportal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:0211";
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
  if (rpm_exists(rpm:"rhevm-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-3.1.0-43.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-backend-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-backend-3.1.0-43.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-config-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-config-3.1.0-43.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-dbscripts-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-dbscripts-3.1.0-43.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-genericapi-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-genericapi-3.1.0-43.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-notification-service-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-notification-service-3.1.0-43.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-restapi-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-restapi-3.1.0-43.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-3.1.0-43.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-allinone-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-allinone-3.1.0-43.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-tools-common-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-tools-common-3.1.0-43.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-userportal-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-userportal-3.1.0-43.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-webadmin-portal-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-webadmin-portal-3.1.0-43.el6ev")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhevm / rhevm-backend / rhevm-config / rhevm-dbscripts / etc");
  }
}
