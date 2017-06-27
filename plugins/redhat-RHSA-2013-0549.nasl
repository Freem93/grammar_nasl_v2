#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0549. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78949);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2012-0833");
  script_bugtraq_id(52044);
  script_osvdb_id(79306);
  script_xref(name:"RHSA", value:"2013:0549");

  script_name(english:"RHEL 5 : Red Hat Directory Server (RHSA-2013:0549)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Red Hat Directory Server and related packages that fix one
security issue and multiple bugs are now available for Red Hat
Directory Server 8.2.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The redhat-ds-base packages provide Red Hat Directory Server, which is
an LDAPv3 compliant server. The base packages include the Lightweight
Directory Access Protocol (LDAP) server and command-line utilities for
server administration.

A flaw was found in the way the 389 Directory Server daemon (ns-slapd)
handled access control instructions (ACIs) using certificate groups.
If an LDAP user that had a certificate group defined attempted to bind
to the directory server, it would cause ns-slapd to enter an infinite
loop and consume an excessive amount of CPU time. (CVE-2012-0833)

Red Hat would like to thank Graham Leggett for reporting this issue.

This update also fixes the following bugs :

* Search with a complex filter that included a range search filter was
slow. (BZ#853004)

* If the server was restarted, or there was some type of connection
failure, it was possible that users were no longer able to log into
the console. Manual action is required to apply this fix: You must add
an aci to each 'cn=Server Group' entry in 'o=netscaperoot', that
allows anonymous/all users read/search rights. (BZ#856089)

* With replication enabled, trying to replace an existing value, where
the new value only differs in case (for example, changing 'cn: foo' to
'cn: FOO'), resulted in the operation failing with an error 20.
(BZ#891866)

All users of Red Hat Directory Server 8.2 should upgrade to these
updated packages, which resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0549.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0833.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:adminutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:adminutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:0549";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"adminutil-1.1.8-3.el5dsrv")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"adminutil-1.1.8-3.el5dsrv")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"adminutil-devel-1.1.8-3.el5dsrv")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"adminutil-devel-1.1.8-3.el5dsrv")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"redhat-ds-base-8.2.11-5.el5dsrv")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"redhat-ds-base-8.2.11-5.el5dsrv")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"redhat-ds-base-devel-8.2.11-5.el5dsrv")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"redhat-ds-base-devel-8.2.11-5.el5dsrv")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "adminutil / adminutil-devel / redhat-ds-base / redhat-ds-base-devel");
  }
}
