#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0788. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66331);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2012-6137");
  script_osvdb_id(93058);
  script_xref(name:"RHSA", value:"2013:0788");

  script_name(english:"RHEL 5 / 6 : subscription-manager (RHSA-2013:0788)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated subscription-manager packages that fix one security issue are
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The subscription-manager packages provide programs and libraries to
allow users to manage subscriptions and yum repositories from the Red
Hat Entitlement platform.

It was discovered that the rhn-migrate-classic-to-rhsm tool did not
verify the Red Hat Network Classic server's X.509 certificate when
migrating system profiles registered with Red Hat Network Classic to
Certificate-based Red Hat Network. An attacker could use this flaw to
conduct man-in-the-middle attacks, allowing them to obtain the user's
Red Hat Network credentials. (CVE-2012-6137)

This issue was discovered by Florian Weimer of the Red Hat Product
Security Team.

All users of subscription-manager are advised to upgrade to these
updated packages, which contain a backported patch to fix this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6137.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0788.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subscription-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subscription-manager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subscription-manager-firstboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subscription-manager-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subscription-manager-migration");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/07");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0788";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"subscription-manager-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"subscription-manager-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"subscription-manager-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"subscription-manager-debuginfo-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"subscription-manager-debuginfo-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"subscription-manager-debuginfo-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"subscription-manager-firstboot-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"subscription-manager-firstboot-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"subscription-manager-firstboot-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"subscription-manager-gui-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"subscription-manager-gui-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"subscription-manager-gui-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"subscription-manager-migration-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"subscription-manager-migration-1.0.24.1-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"subscription-manager-migration-1.0.24.1-1.el5_9")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"subscription-manager-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"subscription-manager-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"subscription-manager-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"subscription-manager-debuginfo-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"subscription-manager-debuginfo-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"subscription-manager-debuginfo-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"subscription-manager-firstboot-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"subscription-manager-firstboot-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"subscription-manager-firstboot-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"subscription-manager-gui-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"subscription-manager-gui-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"subscription-manager-gui-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"subscription-manager-migration-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"subscription-manager-migration-1.1.23.1-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"subscription-manager-migration-1.1.23.1-1.el6_4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subscription-manager / subscription-manager-debuginfo / etc");
  }
}