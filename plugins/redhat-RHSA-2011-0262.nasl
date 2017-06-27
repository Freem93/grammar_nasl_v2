#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0262. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53535);
  script_version ("$Revision: 1.25 $");
  script_cvs_date("$Date: 2017/01/05 14:44:34 $");

  script_cve_id("CVE-2009-4565");
  script_bugtraq_id(37543);
  script_osvdb_id(62373);
  script_xref(name:"RHSA", value:"2011:0262");
  script_xref(name:"IAVA", value:"2010-A-0002");

  script_name(english:"RHEL 4 : sendmail (RHSA-2011:0262)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sendmail packages that fix one security issue and three bugs
are now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Sendmail is a Mail Transport Agent (MTA) used to send mail between
machines.

A flaw was found in the way sendmail handled NUL characters in the
CommonName field of X.509 certificates. An attacker able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority could trick sendmail into accepting it by mistake, allowing
the attacker to perform a man-in-the-middle attack or bypass intended
client certificate authentication. (CVE-2009-4565)

The CVE-2009-4565 issue only affected configurations using TLS with
certificate verification and CommonName checking enabled, which is not
a typical configuration.

This update also fixes the following bugs :

* Previously, sendmail did not correctly handle mail messages that had
a long first header line. A line with more than 2048 characters was
split, causing the part of the line exceeding the limit, as well as
all of the following mail headers, to be incorrectly handled as the
message body. (BZ#499450)

* When an SMTP-sender is sending mail data to sendmail, it may spool
that data to a file in the mail queue. It was found that, if the
SMTP-sender stopped sending data and a timeout occurred, the file may
have been left stalled in the mail queue, instead of being deleted.
This update may not correct this issue for every situation and
configuration. Refer to the Solution section for further information.
(BZ#434645)

* Previously, the sendmail macro MAXHOSTNAMELEN used 64 characters as
the limit for the hostname length. However, in some cases, it was used
against an FQDN length, which has a maximum length of 255 characters.
With this update, the MAXHOSTNAMELEN limit has been changed to 255.
(BZ#485380)

All sendmail users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
this update, sendmail will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-4565.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0262.html"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/22");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0262";
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
  if (rpm_check(release:"RHEL4", reference:"sendmail-8.13.1-6.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"sendmail-cf-8.13.1-6.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"sendmail-devel-8.13.1-6.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"sendmail-doc-8.13.1-6.el4")) flag++;

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
