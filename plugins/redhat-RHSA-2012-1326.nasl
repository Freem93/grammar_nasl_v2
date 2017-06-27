#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1326. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62406);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:17:29 $");

  script_cve_id("CVE-2012-3547");
  script_bugtraq_id(55483);
  script_osvdb_id(85325);
  script_xref(name:"RHSA", value:"2012:1326");

  script_name(english:"RHEL 6 : freeradius (RHSA-2012:1326)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freeradius packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

FreeRADIUS is a high-performance and highly configurable free Remote
Authentication Dial In User Service (RADIUS) server, designed to allow
centralized authentication and authorization for a network.

A buffer overflow flaw was discovered in the way radiusd handled the
expiration date field in X.509 client certificates. A remote attacker
could possibly use this flaw to crash radiusd if it were configured to
use the certificate or TLS tunnelled authentication methods (such as
EAP-TLS, EAP-TTLS, and PEAP). (CVE-2012-3547)

Red Hat would like to thank Timo Warns of PRESENSE Technologies GmbH
for reporting this issue.

Users of FreeRADIUS are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the update, radiusd will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1326.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:1326";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-debuginfo-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-debuginfo-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-debuginfo-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-krb5-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-krb5-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-krb5-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-ldap-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-ldap-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-ldap-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-mysql-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-mysql-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-mysql-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-perl-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-perl-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-perl-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-postgresql-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-postgresql-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-postgresql-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-python-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-python-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-python-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-unixODBC-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-unixODBC-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-unixODBC-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-utils-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-utils-2.1.12-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-utils-2.1.12-4.el6_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius / freeradius-debuginfo / freeradius-krb5 / etc");
  }
}
