#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0868. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43833);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/29 15:45:04 $");

  script_cve_id("CVE-2007-4132");
  script_osvdb_id(40438);
  script_xref(name:"RHSA", value:"2007:0868");

  script_name(english:"RHEL 4 : Satellite Server (RHSA-2007:0868)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Network Satellite Server version 5.0.1 is now available which
fixes a security issue in version 5.0.0.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

During an internal code audit, a flaw was found in an unused back-end
XMLRPC handler first added to Red Hat Network Satellite Server 5.0.0.
A remote attacker with valid authentication credentials who was able
to connect to a Satellite Server could use this flaw to execute
arbitrary code on the server as the 'apache' user. (CVE-2007-4132)

Users of Red Hat Network Satellite Server 5.0.0 are advised to upgrade
to 5.0.1 which removes the unused, vulnerable handler.

Note: This issue did not affect the hosted version of Red Hat Network
or versions of Red Hat Network Satellite Server prior to 5.0.0."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4132.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0868.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-config-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-config-files-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-config-files-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-package-push-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-satellite-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-xml-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-xp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0868";
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

  if (! (rpm_exists(release:"RHEL4", rpm:"rhns-app-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite Server");

  if (rpm_check(release:"RHEL4", reference:"rhns-5.0.1-10")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhns-app-5.0.1-10")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhns-applet-5.0.1-10")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhns-config-files-5.0.1-10")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhns-config-files-common-5.0.1-10")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhns-config-files-tool-5.0.1-10")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhns-package-push-server-5.0.1-10")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhns-satellite-tools-5.0.1-10")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhns-server-5.0.1-10")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhns-sql-5.0.1-10")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhns-xml-export-libs-5.0.1-10")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhns-xmlrpc-5.0.1-10")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhns-xp-5.0.1-10")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhns / rhns-app / rhns-applet / rhns-config-files / etc");
  }
}
