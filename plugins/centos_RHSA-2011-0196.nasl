#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0196 and 
# CentOS Errata and Security Advisory 2011:0196 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53416);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/28 23:54:24 $");

  script_cve_id("CVE-2010-3710", "CVE-2010-4156", "CVE-2010-4645");
  script_bugtraq_id(43926, 44727, 45668);
  script_xref(name:"RHSA", value:"2011:0196");

  script_name(english:"CentOS 5 : php53 (CESA-2011:0196)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php53 packages that fix three security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

A flaw was found in the way PHP converted certain floating point
values from string representation to a number. If a PHP script
evaluated an attacker's input in a numeric context, the PHP
interpreter could cause high CPU usage until the script execution time
limit is reached. This issue only affected i386 systems.
(CVE-2010-4645)

A stack memory exhaustion flaw was found in the way the PHP
filter_var() function validated email addresses. An attacker could use
this flaw to crash the PHP interpreter by providing excessively long
input to be validated as an email address. (CVE-2010-3710)

A memory disclosure flaw was found in the PHP multi-byte string
extension. If the mb_strcut() function was called with a length
argument exceeding the input string size, the function could disclose
a portion of the PHP interpreter's memory. (CVE-2010-4156)

All php53 users should upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017379.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0394326"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017380.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b21186c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php53 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"php53-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-bcmath-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-cli-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-common-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-dba-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-devel-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-gd-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-imap-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-intl-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-ldap-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-mbstring-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-mysql-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-odbc-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pdo-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pgsql-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-process-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pspell-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-snmp-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-soap-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-xml-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-xmlrpc-5.3.3-1.el5_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
