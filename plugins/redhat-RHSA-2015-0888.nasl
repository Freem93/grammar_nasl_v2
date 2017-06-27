#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0888. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83161);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/06 16:01:51 $");

  script_cve_id("CVE-2015-0237", "CVE-2015-0257");
  script_bugtraq_id(74394, 74396);
  script_xref(name:"RHSA", value:"2015:0888");

  script_name(english:"RHEL 6 : Virtualization Manager (RHSA-2015:0888)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Enterprise Virtualization Manager 3.5.1 is now available.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Enterprise Virtualization Manager is a visual tool for
centrally managing collections of virtual servers running Red Hat
Enterprise Linux and Microsoft Windows. This package also includes the
Red Hat Enterprise Virtualization Manager API, a set of scriptable
commands that give administrators the ability to perform queries and
operations on Red Hat Enterprise Virtualization Manager.

The Manager is a JBoss Application Server application that provides
several interfaces through which the virtual environment can be
accessed and interacted with, including an Administration Portal, a
User Portal, and a Representational State Transfer (REST) Application
Programming Interface (API).

It was discovered that the permissions to allow or deny snapshot
creation were ignored during live storage migration of a VM's disk
between storage domains. An attacker able to live migrate a disk
between storage domains could use this flaw to cause a denial of
service. (CVE-2015-0237)

It was discovered that a directory shared between the
ovirt-engine-dwhd service and a plug-in used during the service's
startup had incorrect permissions. A local user could use this flaw to
access files in this directory, which could potentially contain
sensitive information. (CVE-2015-0257)

The CVE-2015-0237 issue was discovered by Red Hat Enterprise
Visualization Engineering, and the CVE-2015-0257 issue was discovered
by Yedidyah Bar David of the Red Hat Enterprise Virtualization team.

These updated Red Hat Enterprise Virtualization Manager packages also
include numerous bug fixes and various enhancements. Space precludes
documenting all of these changes in this advisory. Users are directed
to the Red Hat Enterprise Virtualization 3.5 Technical Notes, linked
to in the References, for information on the most significant of these
changes.

All Red Hat Enterprise Virtualization Manager users are advised to
upgrade to these updated packages, which resolve these issues and add
these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0237.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0257.html"
  );
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Virtualization
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?568a49ce"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0888.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-extensions-api-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-extensions-api-impl-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-allinone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-ovirt-engine-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-userportal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/30");
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
  rhsa = "RHSA-2015:0888";
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
  if (rpm_exists(rpm:"rhevm-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-backend-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-backend-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-dbscripts-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-dbscripts-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-extensions-api-impl-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-extensions-api-impl-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-extensions-api-impl-javadoc-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-extensions-api-impl-javadoc-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-lib-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-lib-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-restapi-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-restapi-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-base-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-base-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-allinone-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-allinone-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-ovirt-engine-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-ovirt-engine-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-ovirt-engine-common-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-ovirt-engine-common-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-websocket-proxy-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-websocket-proxy-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-tools-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-tools-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-userportal-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-userportal-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-webadmin-portal-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-webadmin-portal-3.5.1-0.4.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-websocket-proxy-3.5.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-websocket-proxy-3.5.1-0.4.el6ev")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhevm / rhevm-backend / rhevm-dbscripts / rhevm-extensions-api-impl / etc");
  }
}
