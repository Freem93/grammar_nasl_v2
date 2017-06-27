#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1451. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41008);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2003-0967", "CVE-2009-3111");
  script_xref(name:"RHSA", value:"2009:1451");

  script_name(english:"RHEL 5 : freeradius (RHSA-2009:1451)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freeradius packages that fix a security issue are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

FreeRADIUS is a high-performance and highly configurable free Remote
Authentication Dial In User Service (RADIUS) server, designed to allow
centralized authentication and authorization for a network.

An input validation flaw was discovered in the way FreeRADIUS decoded
specific RADIUS attributes from RADIUS packets. A remote attacker
could use this flaw to crash the RADIUS daemon (radiusd) via a
specially crafted RADIUS packet. (CVE-2009-3111)

Users of FreeRADIUS are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the update, radiusd will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3111.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1451.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2009:1451";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"freeradius-1.1.3-1.5.el5_4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"freeradius-1.1.3-1.5.el5_4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"freeradius-1.1.3-1.5.el5_4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"freeradius-mysql-1.1.3-1.5.el5_4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"freeradius-mysql-1.1.3-1.5.el5_4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"freeradius-mysql-1.1.3-1.5.el5_4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"freeradius-postgresql-1.1.3-1.5.el5_4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"freeradius-postgresql-1.1.3-1.5.el5_4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"freeradius-postgresql-1.1.3-1.5.el5_4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"freeradius-unixODBC-1.1.3-1.5.el5_4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"freeradius-unixODBC-1.1.3-1.5.el5_4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"freeradius-unixODBC-1.1.3-1.5.el5_4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius / freeradius-mysql / freeradius-postgresql / etc");
  }
}
