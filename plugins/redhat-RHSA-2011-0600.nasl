#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0600. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54597);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2010-3707", "CVE-2010-3780");
  script_bugtraq_id(43690);
  script_xref(name:"RHSA", value:"2011:0600");

  script_name(english:"RHEL 6 : dovecot (RHSA-2011:0600)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dovecot packages that fix two security issues and add one
enhancement are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Dovecot is an IMAP server for Linux, UNIX, and similar operating
systems, primarily written with security in mind.

A flaw was found in the way Dovecot handled SIGCHLD signals. If a
large amount of IMAP or POP3 session disconnects caused the Dovecot
master process to receive these signals rapidly, it could cause the
master process to crash. (CVE-2010-3780)

A flaw was found in the way Dovecot processed multiple Access Control
Lists (ACL) defined for a mailbox. In some cases, Dovecot could fail
to apply the more specific ACL entry, possibly resulting in more
access being granted to the user than intended. (CVE-2010-3707)

This update also adds the following enhancement :

* This erratum upgrades Dovecot to upstream version 2.0.9, providing
multiple fixes for the 'dsync' utility and improving overall
performance. Refer to the '/usr/share/doc/dovecot-2.0.9/ChangeLog'
file after installing this update for further information about the
changes. (BZ#637056)

Users of dovecot are advised to upgrade to these updated packages,
which resolve these issues and add this enhancement. After installing
the updated packages, the dovecot service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3707.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3780.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0600.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot-pigeonhole");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/20");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0600";
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
  if (rpm_check(release:"RHEL6", reference:"dovecot-2.0.9-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"dovecot-debuginfo-2.0.9-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dovecot-devel-2.0.9-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dovecot-devel-2.0.9-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dovecot-devel-2.0.9-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dovecot-mysql-2.0.9-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dovecot-mysql-2.0.9-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dovecot-mysql-2.0.9-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dovecot-pgsql-2.0.9-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dovecot-pgsql-2.0.9-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dovecot-pgsql-2.0.9-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dovecot-pigeonhole-2.0.9-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dovecot-pigeonhole-2.0.9-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dovecot-pigeonhole-2.0.9-2.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot / dovecot-debuginfo / dovecot-devel / dovecot-mysql / etc");
  }
}
