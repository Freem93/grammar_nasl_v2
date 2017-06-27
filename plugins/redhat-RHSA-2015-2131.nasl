#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2131. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86970);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/01/06 16:01:53 $");

  script_cve_id("CVE-2015-3276");
  script_osvdb_id(124934, 144050);
  script_xref(name:"RHSA", value:"2015:2131");

  script_name(english:"RHEL 7 : openldap (RHSA-2015:2131)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix one security issue, several bugs,
and add one enhancement are now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

OpenLDAP is an open source suite of Lightweight Directory Access
Protocol (LDAP) applications and development tools. LDAP is a set of
protocols used to access and maintain distributed directory
information services over an IP network. The openldap packages contain
configuration files, libraries, and documentation for OpenLDAP.

A flaw was found in the way OpenLDAP parsed OpenSSL-style cipher
strings. As a result, OpenLDAP could potentially use ciphers that were
not intended to be enabled. (CVE-2015-3276)

This issue was discovered by Martin Poole of the Red Hat Software
Maintenance Engineering group.

The openldap packages have been upgraded to upstream version 2.4.40,
which provides a number of bug fixes and one enhancement over the
previous version :

* The ORDERING matching rules have been added to the ppolicy attribute
type descriptions. * The server no longer terminates unexpectedly when
processing SRV records. * Missing objectClass information has been
added, which enables the user to modify the front-end configuration by
standard means.

(BZ#1147982)

This update also fixes the following bugs :

* Previously, OpenLDAP did not properly handle a number of
simultaneous updates. As a consequence, sending a number of parallel
update requests to the server could cause a deadlock. With this
update, a superfluous locking mechanism causing the deadlock has been
removed, thus fixing the bug. (BZ#1125152)

* The httpd service sometimes terminated unexpectedly with a
segmentation fault on the libldap library unload. The underlying
source code has been modified to prevent a bad memory access error
that caused the bug to occur. As a result, httpd no longer crashes in
this situation. (BZ#1158005)

* After upgrading the system from Red Hat Enterprise Linux 6 to Red
Hat Enterprise Linux 7, symbolic links to certain libraries
unexpectedly pointed to locations belonging to the openldap-devel
package. If the user uninstalled openldap-devel, the symbolic links
were broken and the 'rpm -V openldap' command sometimes produced
errors. With this update, the symbolic links no longer get broken in
the described situation. If the user downgrades openldap to version
2.4.39-6 or earlier, the symbolic links might break. After such
downgrade, it is recommended to verify that the symbolic links did not
break. To do this, make sure the yum-plugin-verify package is
installed and obtain the target libraries by running the 'rpm -V
openldap' or 'yum verify openldap' command. (BZ#1230263)

In addition, this update adds the following enhancement :

* OpenLDAP clients now automatically choose the Network Security
Services (NSS) default cipher suites for communication with the
server. It is no longer necessary to maintain the default cipher
suites manually in the OpenLDAP source code. (BZ#1245279)

All openldap users are advised to upgrade to these updated packages,
which correct these issues and add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3276.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2131.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2131";
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
  if (rpm_check(release:"RHEL7", reference:"openldap-2.4.40-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openldap-clients-2.4.40-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openldap-clients-2.4.40-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"openldap-debuginfo-2.4.40-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"openldap-devel-2.4.40-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openldap-servers-2.4.40-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openldap-servers-2.4.40-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openldap-servers-sql-2.4.40-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openldap-servers-sql-2.4.40-8.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap / openldap-clients / openldap-debuginfo / openldap-devel / etc");
  }
}
