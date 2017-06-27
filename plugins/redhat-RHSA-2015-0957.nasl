#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0957. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83343);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/06 16:01:51 $");

  script_cve_id("CVE-2014-8162");
  script_xref(name:"RHSA", value:"2015:0957");

  script_name(english:"RHEL 6 : spacewalk-java (RHSA-2015:0957)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated spacewalk packages that fix one security issue are now
available for Red Hat Satellite 5.7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Red Hat Satellite is a system management tool for Linux-based
infrastructures. It allows for provisioning, monitoring, and remote
management of multiple Linux deployments with a single, centralized
tool.

It was found that the RPC interface in Satellite would resolve
external entities, allowing an attacker to conduct XML External Entity
(XXE) attacks. A remote attacker could use this flaw to read files
accessible to the user running the Satellite server, and potentially
perform other more advanced XXE attacks. (CVE-2014-8162)

Red Hat would like to thank Travis Emmert for reporting this issue.

All spacewalk users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8162.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0957.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected packages. Note that while Satellite 5.6 and below
are affected, Red Hat does not plan to release a fix for those
versions."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");
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
  rhsa = "RHSA-2015:0957";
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
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-2.3.8-103.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-config-2.3.8-103.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-lib-2.3.8-103.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-oracle-2.3.8-103.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-postgresql-2.3.8-103.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-setup-2.3.0-17.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-taskomatic-2.3.8-103.el6sat")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + 'NOTE: This fixed version requires Satellite 5.7 to apply the patch, but\nversions of RedHat Satellite prior to 5.7 are still affected.\n'  + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spacewalk-java / spacewalk-java-config / spacewalk-java-lib / etc");
  }
}
