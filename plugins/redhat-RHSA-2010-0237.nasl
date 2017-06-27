#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0237. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46286);
  script_version ("$Revision: 1.25 $");
  script_cvs_date("$Date: 2017/01/05 14:44:34 $");

  script_cve_id("CVE-2006-7176", "CVE-2009-4565");
  script_bugtraq_id(37543);
  script_osvdb_id(62373);
  script_xref(name:"RHSA", value:"2010:0237");
  script_xref(name:"IAVA", value:"2010-A-0002");

  script_name(english:"RHEL 5 : sendmail (RHSA-2010:0237)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sendmail packages that fix two security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Sendmail is a very widely used Mail Transport Agent (MTA). MTAs
deliver mail from one machine to another. Sendmail is not a client
program, but rather a behind-the-scenes daemon that moves email over
networks or the Internet to its final destination.

The configuration of sendmail in Red Hat Enterprise Linux was found to
not reject the 'localhost.localdomain' domain name for email messages
that come from external hosts. This could allow remote attackers to
disguise spoofed messages. (CVE-2006-7176)

A flaw was found in the way sendmail handled NUL characters in the
CommonName field of X.509 certificates. An attacker able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority could trick sendmail into accepting it by mistake, allowing
the attacker to perform a man-in-the-middle attack or bypass intended
client certificate authentication. (CVE-2009-4565)

Note: The CVE-2009-4565 issue only affected configurations using TLS
with certificate verification and CommonName checking enabled, which
is not a typical configuration.

This update also fixes the following bugs :

* sendmail was unable to parse files specified by the
ServiceSwitchFile option which used a colon as a separator.
(BZ#512871)

* sendmail incorrectly returned a zero exit code when free space was
low. (BZ#299951)

* the sendmail manual page had a blank space between the -qG option
and parameter. (BZ#250552)

* the comments in the sendmail.mc file specified the wrong path to SSL
certificates. (BZ#244012)

* the sendmail packages did not provide the MTA capability.
(BZ#494408)

All users of sendmail are advised to upgrade to these updated
packages, which resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-7176.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-4565.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0237.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sendmail-cf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sendmail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sendmail-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2010:0237";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sendmail-8.13.8-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sendmail-8.13.8-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sendmail-8.13.8-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sendmail-cf-8.13.8-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sendmail-cf-8.13.8-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sendmail-cf-8.13.8-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"sendmail-devel-8.13.8-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sendmail-doc-8.13.8-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sendmail-doc-8.13.8-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sendmail-doc-8.13.8-8.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sendmail / sendmail-cf / sendmail-devel / sendmail-doc");
  }
}
