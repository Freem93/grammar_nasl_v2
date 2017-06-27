#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:751. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20044);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 18:06:54 $");

  script_cve_id("CVE-2004-0823", "CVE-2005-2069");
  script_xref(name:"RHSA", value:"2005:751");

  script_name(english:"RHEL 2.1 / 3 : openldap and nss_ldap (RHSA-2005:751)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap and nss_ldap packages that correct a potential
password disclosure issue are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools.

The nss_ldap module is an extension for use with GNU libc which allows
applications to, without internal modification, consult a directory
service using LDAP to supplement information that would be read from
local files such as /etc/passwd, /etc/group, and /etc/shadow.

A bug was found in the way OpenLDAP, nss_ldap, and pam_ldap refer LDAP
servers. If a client connection is referred to a different server, it
is possible that the referred connection will not be encrypted even if
the client has 'ssl start_tls' in its ldap.conf file. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-2069 to this issue.

A bug was also found in the way certain OpenLDAP authentication
schemes store hashed passwords. A remote attacker could re-use a
hashed password to gain access to unauthorized resources. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2004-0823 to this issue.

All users of OpenLDAP and nss_ldap are advised to upgrade to these
updated packages, which contain backported fixes that resolve these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0823.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-2069.html"
  );
  # http://marc.theaimsgroup.com/?l=pamldap&m=112432721728160&w=2
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=pamldap&m=112432721728160&w=2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-751.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:751";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"nss_ldap-189-13")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openldap-2.0.27-4.9")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openldap-clients-2.0.27-4.9")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openldap-devel-2.0.27-4.9")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openldap-servers-2.0.27-4.9")) flag++;

  if (rpm_check(release:"RHEL3", reference:"nss_ldap-207-17")) flag++;
  if (rpm_check(release:"RHEL3", reference:"openldap-2.0.27-20")) flag++;
  if (rpm_check(release:"RHEL3", reference:"openldap-clients-2.0.27-20")) flag++;
  if (rpm_check(release:"RHEL3", reference:"openldap-devel-2.0.27-20")) flag++;
  if (rpm_check(release:"RHEL3", reference:"openldap-servers-2.0.27-20")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss_ldap / openldap / openldap-clients / openldap-devel / etc");
  }
}
