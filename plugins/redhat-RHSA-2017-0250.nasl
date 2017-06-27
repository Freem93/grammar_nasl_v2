#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0250. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96973);
  script_version("$Revision: 3.6 $");
  script_cvs_date("$Date: 2017/03/28 14:02:06 $");

  script_cve_id("CVE-2016-6816", "CVE-2016-7061", "CVE-2016-8627", "CVE-2016-8656");
  script_osvdb_id(146776, 147619, 150615, 151320);
  script_xref(name:"RHSA", value:"2017:0250");
  script_xref(name:"IAVA", value:"2017-A-0027");

  script_name(english:"RHEL 6 : jboss-ec2-eap (RHSA-2017:0250)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for jboss-ec2-eap is now available for Red Hat JBoss
Enterprise Application Platform 6.4 for RHEL 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The jboss-ec2-eap package provide scripts for Red Hat JBoss Enterprise
Application Platform running on the Amazon Web Services (AWS) Elastic
Compute Cloud (EC2).

With this update, the jboss-ec2-eap package has been updated to ensure
compatibility with Red Hat JBoss Enterprise Application Platform
6.4.12.

Security Fix(es) :

* It was discovered that the jboss init script performed unsafe file
handling which could result in local privilege escalation.
(CVE-2016-8656)

* It was discovered that the code that parsed the HTTP request line
permitted invalid characters. This could be exploited, in conjunction
with a proxy that also permitted the invalid characters but with a
different interpretation, to inject data into the HTTP response. By
manipulating the HTTP response the attacker could poison a web-cache,
perform an XSS attack and/or obtain sensitive information from
requests other then their own. (CVE-2016-6816)

* An EAP feature to download server log files allows logs to be
available via GET requests making them vulnerable to cross-origin
attacks. An attacker could trigger the user's browser to request the
log files consuming enough resources that normal server functioning
could be impaired. (CVE-2016-8627)

* It was discovered that when configuring RBAC and marking information
as sensitive, users with a Monitor role are able to view the sensitive
information. (CVE-2016-7061)

The CVE-2016-8627 issue was discovered by Darran Lofthouse and Brian
Stansberry (Red Hat)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-6816.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-7061.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-8627.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-8656.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-US/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0250.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected jboss-ec2-eap and / or jboss-ec2-eap-samples
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ec2-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ec2-eap-samples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/03");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2017:0250";
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
  if (rpm_check(release:"RHEL6", reference:"jboss-ec2-eap-7.5.13-1.Final_redhat_2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ec2-eap-samples-7.5.13-1.Final_redhat_2.ep6.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jboss-ec2-eap / jboss-ec2-eap-samples");
  }
}
