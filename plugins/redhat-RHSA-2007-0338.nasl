#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0338. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25213);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/29 15:35:21 $");

  script_cve_id("CVE-2007-2028");
  script_bugtraq_id(23466);
  script_osvdb_id(34912);
  script_xref(name:"RHSA", value:"2007:0338");

  script_name(english:"RHEL 3 / 4 / 5 : freeradius (RHSA-2007:0338)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freeradius packages that fix a memory leak flaw are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

FreeRADIUS is a high-performance and highly configurable free RADIUS
server designed to allow centralized authentication and authorization
for a network.

A memory leak flaw was found in the way FreeRADIUS parses certain
authentication requests. A remote attacker could send a specially
crafted authentication request which could cause FreeRADIUS to leak a
small amount of memory. If enough of these requests are sent, the
FreeRADIUS daemon would consume a vast quantity of system memory
leading to a possible denial of service. (CVE-2007-2028)

Users of FreeRADIUS should update to these erratum packages, which
contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0338.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0338";
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
  if (rpm_check(release:"RHEL3", reference:"freeradius-1.0.1-2.RHEL3.4")) flag++;


  if (rpm_check(release:"RHEL4", reference:"freeradius-1.0.1-3.RHEL4.5")) flag++;

  if (rpm_check(release:"RHEL4", reference:"freeradius-mysql-1.0.1-3.RHEL4.5")) flag++;

  if (rpm_check(release:"RHEL4", reference:"freeradius-postgresql-1.0.1-3.RHEL4.5")) flag++;

  if (rpm_check(release:"RHEL4", reference:"freeradius-unixODBC-1.0.1-3.RHEL4.5")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"freeradius-1.1.3-1.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"freeradius-1.1.3-1.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"freeradius-1.1.3-1.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"freeradius-mysql-1.1.3-1.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"freeradius-mysql-1.1.3-1.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"freeradius-mysql-1.1.3-1.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"freeradius-postgresql-1.1.3-1.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"freeradius-postgresql-1.1.3-1.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"freeradius-postgresql-1.1.3-1.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"freeradius-unixODBC-1.1.3-1.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"freeradius-unixODBC-1.1.3-1.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"freeradius-unixODBC-1.1.3-1.2.el5")) flag++;


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
