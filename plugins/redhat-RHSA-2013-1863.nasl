#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1863. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76187);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:29:45 $");

  script_cve_id("CVE-2013-6439");
  script_bugtraq_id(64515);
  script_osvdb_id(101389);
  script_xref(name:"RHSA", value:"2013:1863");

  script_name(english:"RHEL 6 : candlepin in Subscription Asset Manager (RHSA-2013:1863)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated candlepin packages that fix one security issue are now
available for Red Hat Subscription Asset Manager.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Candlepin is an open source entitlement management system. It tracks
the products which an owner has subscribed too, and allows the owner
to consume the subscriptions based on configurable business rules.

It was discovered that, by default, Candlepin enabled a very weak
authentication scheme if no setting was specified in the configuration
file. (CVE-2013-6439)

This issue was discovered by Adrian Likins of Red Hat.

Note: The configuration file as supplied by Subscription Asset Manager
1.2 and 1.3 had this unsafe authentication mode disabled; however,
users who have upgraded from Subscription Asset Manager 1.1 or earlier
and who have not added 'candlepin.auth.trusted.enable = false' to the
Candlepin configuration will be affected by this issue.

Users of Subscription Asset Manager 1.0 or 1.1 who cannot upgrade
should add the following to '/etc/candlepin/candlepin.conf' :

candlepin.auth.trusted.enable = false candlepin.auth.trusted.enabled =
false

Users of Subscription Asset Manager 1.2 or 1.3 who cannot upgrade
should only need to add :

candlepin.auth.trusted.enable = false

Installing this upgrade disables the unsafe authentication scheme
unless it is specifically enabled in the configuration.

Users of Red Hat Subscription Asset Manager are advised to upgrade to
these updated packages, which correct this issue. Candlepin must be
restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6439.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1863.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected candlepin, candlepin-selinux and / or
candlepin-tomcat6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-tomcat6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/23");
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
  rhsa = "RHSA-2013:1863";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"candlepin-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Subscription Asset Manager");

  if (rpm_check(release:"RHEL6", reference:"candlepin-0.8.26.0-1.el6sam")) flag++;
  if (rpm_check(release:"RHEL6", reference:"candlepin-selinux-0.8.26.0-1.el6sam")) flag++;
  if (rpm_check(release:"RHEL6", reference:"candlepin-tomcat6-0.8.26.0-1.el6sam")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "candlepin / candlepin-selinux / candlepin-tomcat6");
  }
}
