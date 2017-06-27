#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1427. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40901);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2007-4565", "CVE-2008-2711", "CVE-2009-2666");
  script_bugtraq_id(25495, 29705);
  script_xref(name:"RHSA", value:"2009:1427");

  script_name(english:"RHEL 3 / 4 / 5 : fetchmail (RHSA-2009:1427)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated fetchmail package that fixes multiple security issues is
now available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Fetchmail is a remote mail retrieval and forwarding utility intended
for use over on-demand TCP/IP links, such as SLIP and PPP connections.

It was discovered that fetchmail is affected by the previously
published 'null prefix attack', caused by incorrect handling of NULL
characters in X.509 certificates. If an attacker is able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority, the attacker could use the certificate during a
man-in-the-middle attack and potentially confuse fetchmail into
accepting it by mistake. (CVE-2009-2666)

A flaw was found in the way fetchmail handles rejections from a remote
SMTP server when sending warning mail to the postmaster. If fetchmail
sent a warning mail to the postmaster of an SMTP server and that SMTP
server rejected it, fetchmail could crash. (CVE-2007-4565)

A flaw was found in fetchmail. When fetchmail is run in double verbose
mode ('-v -v'), it could crash upon receiving certain, malformed mail
messages with long headers. A remote attacker could use this flaw to
cause a denial of service if fetchmail was also running in daemon mode
('-d'). (CVE-2008-2711)

Note: when using SSL-enabled services, it is recommended that the
fetchmail '--sslcertck' option be used to enforce strict SSL
certificate checking.

All fetchmail users should upgrade to this updated package, which
contains backported patches to correct these issues. If fetchmail is
running in daemon mode, it must be restarted for this update to take
effect (use the 'fetchmail --quit' command to stop the fetchmail
process)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4565.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2711.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2666.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1427.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fetchmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fetchmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/09");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1427";
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
  if (rpm_check(release:"RHEL3", reference:"fetchmail-6.2.0-3.el3.5")) flag++;


  if (rpm_check(release:"RHEL4", reference:"fetchmail-6.2.5-6.0.1.el4_8.1")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"fetchmail-6.3.6-1.1.el5_3.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"fetchmail-6.3.6-1.1.el5_3.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"fetchmail-6.3.6-1.1.el5_3.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fetchmail");
  }
}
