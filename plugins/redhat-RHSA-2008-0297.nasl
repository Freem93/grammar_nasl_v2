#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0297. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32423);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2007-2231", "CVE-2007-4211", "CVE-2007-6598", "CVE-2008-1199");
  script_bugtraq_id(28092);
  script_xref(name:"RHSA", value:"2008:0297");

  script_name(english:"RHEL 5 : dovecot (RHSA-2008:0297)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated dovecot package that fixes several security issues and
various bugs is now available for Red Hat Enterprise Linux 5.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Dovecot is an IMAP server for Linux and UNIX-like systems, primarily
written with security in mind.

A flaw was discovered in the way Dovecot handled the
'mail_extra_groups' option. An authenticated attacker with local shell
access could leverage this flaw to read, modify, or delete other users
mail that is stored on the mail server. (CVE-2008-1199)

This issue did not affect the default Red Hat Enterprise Linux 5
Dovecot configuration. This update adds two new configuration options
-- 'mail_privileged_group' and 'mail_access_groups' -- to minimize the
usage of additional privileges.

A directory traversal flaw was discovered in Dovecot's zlib plug-in.
An authenticated user could use this flaw to view other compressed
mailboxes with the permissions of the Dovecot process. (CVE-2007-2231)

A flaw was found in the Dovecot ACL plug-in. User with only insert
permissions for a mailbox could use the 'COPY' and 'APPEND' commands
to set additional message flags. (CVE-2007-4211)

A flaw was found in a way Dovecot cached LDAP query results in certain
configurations. This could possibly allow authenticated users to log
in as a different user who has the same password. (CVE-2007-6598)

As well, this updated package fixes the following bugs :

* configuring 'userdb' and 'passdb' to use LDAP caused Dovecot to
hang. A segmentation fault may have occurred. In this updated package,
using an LDAP backend for 'userdb' and 'passdb' no longer causes
Dovecot to hang.

* the Dovecot 'login_process_size' limit was configured for 32-bit
systems. On 64-bit systems, when Dovecot was configured to use either
IMAP or POP3, the log in processes crashed with out-of-memory errors.
Errors such as the following were logged :

pop3-login: pop3-login: error while loading shared libraries:
libsepol.so.1: failed to map segment from shared object: Cannot
allocate memory

In this updated package, the 'login_process_size' limit is correctly
configured on 64-bit systems, which resolves this issue.

Note: this updated package upgrades dovecot to version 1.0.7. For
further details, refer to the Dovecot changelog:
http://koji.fedoraproject.org/koji/buildinfo?buildID=23397

Users of dovecot are advised to upgrade to this updated package, which
resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2231.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4211.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6598.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1199.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0297.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 59, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2008:0297";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"dovecot-1.0.7-2.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"dovecot-1.0.7-2.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"dovecot-1.0.7-2.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot");
  }
}
