#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0205. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35433);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/03 17:16:35 $");

  script_cve_id("CVE-2008-4577", "CVE-2008-4870");
  script_bugtraq_id(31587);
  script_xref(name:"RHSA", value:"2009:0205");

  script_name(english:"RHEL 5 : dovecot (RHSA-2009:0205)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated dovecot package that corrects two security flaws and
various bugs is now available for Red Hat Enterprise Linux 5.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Dovecot is an IMAP server for Linux and UNIX-like systems, primarily
written with security in mind.

A flaw was found in Dovecot's ACL plug-in. The ACL plug-in treated
negative access rights as positive rights, which could allow an
attacker to bypass intended access restrictions. (CVE-2008-4577)

A password disclosure flaw was found with Dovecot's configuration
file. If a system had the 'ssl_key_password' option defined, any local
user could view the SSL key password. (CVE-2008-4870)

Note: This flaw did not allow the attacker to acquire the contents of
the SSL key. The password has no value without the key file which
arbitrary users should not have read access to.

To better protect even this value, however, the dovecot.conf file now
supports the '!include_try' directive. The ssl_key_password option
should be moved from dovecot.conf to a new file owned by, and only
readable and writable by, root (ie 0600). This file should be
referenced from dovecot.conf by setting the '!include_try
[/path/to/password/file]' option.

Additionally, this update addresses the following bugs :

* the dovecot init script -- /etc/rc.d/init.d/dovecot -- did not check
if the dovecot binary or configuration files existed. It also used the
wrong pid file for checking the dovecot service's status. This update
includes a new init script that corrects these errors.

* the %files section of the dovecot spec file did not include '%dir
%{ssldir}/private'. As a consequence, the /etc/pki/private/ directory
was not owned by dovecot. (Note: files inside /etc/pki/private/ were
and are owned by dovecot.) With this update, the missing line has been
added to the spec file, and the noted directory is now owned by
dovecot.

* in some previously released versions of dovecot, the authentication
process accepted (and passed along un-escaped) passwords containing
characters that had special meaning to dovecot's internal protocols.
This updated release prevents such passwords from being passed back,
instead returning the error, 'Attempted login with password having
illegal chars'.

Note: dovecot versions previously shipped with Red Hat Enterprise
Linux 5 did not allow this behavior. This update addresses the issue
above but said issue was only present in versions of dovecot not
previously included with Red Hat Enterprise Linux 5.

Users of dovecot are advised to upgrade to this updated package, which
addresses these vulnerabilities and resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4577.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4870.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-0205.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/21");
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
  rhsa = "RHSA-2009:0205";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"dovecot-1.0.7-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"dovecot-1.0.7-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"dovecot-1.0.7-7.el5")) flag++;

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
