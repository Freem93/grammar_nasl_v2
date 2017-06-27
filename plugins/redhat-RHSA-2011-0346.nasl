#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0346. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52627);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/04 16:02:21 $");

  script_cve_id("CVE-2011-1024", "CVE-2011-1025", "CVE-2011-1081");
  script_osvdb_id(72528, 72529, 72530);
  script_xref(name:"RHSA", value:"2011:0346");

  script_name(english:"RHEL 5 : openldap (RHSA-2011:0346)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools.

A flaw was found in the way OpenLDAP handled authentication failures
being passed from an OpenLDAP slave to the master. If OpenLDAP was
configured with a chain overlay and it forwarded authentication
failures, OpenLDAP would bind to the directory as an anonymous user
and return success, rather than return failure on the authenticated
bind. This could allow a user on a system that uses LDAP for
authentication to log into a directory-based account without knowing
the password. (CVE-2011-1024)

This update also fixes the following bug :

* Previously, multiple concurrent connections to an OpenLDAP server
could cause the slapd service to terminate unexpectedly with an
assertion error. This update adds mutexes to protect multiple threads
from accessing a structure with a connection, and the slapd service no
longer crashes. (BZ#677611)

Users of OpenLDAP should upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
this update, the OpenLDAP daemons will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0346.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers-overlays");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2011:0346";
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
  if (rpm_check(release:"RHEL5", reference:"compat-openldap-2.3.43_2.2.29-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", reference:"openldap-2.3.43-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openldap-clients-2.3.43-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openldap-clients-2.3.43-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openldap-clients-2.3.43-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", reference:"openldap-devel-2.3.43-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openldap-servers-2.3.43-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openldap-servers-2.3.43-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openldap-servers-2.3.43-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openldap-servers-overlays-2.3.43-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openldap-servers-overlays-2.3.43-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openldap-servers-overlays-2.3.43-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openldap-servers-sql-2.3.43-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openldap-servers-sql-2.3.43-12.el5_6.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openldap-servers-sql-2.3.43-12.el5_6.7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openldap / openldap / openldap-clients / openldap-devel / etc");
  }
}
