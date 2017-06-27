#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-105.
#

include("compat.inc");

if (description)
{
  script_id(69595);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2011-4623");
  script_xref(name:"ALAS", value:"2012-105");
  script_xref(name:"RHSA", value:"2012:0796");

  script_name(english:"Amazon Linux AMI : rsyslog (ALAS-2012-105)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A numeric truncation error, leading to a heap-based buffer overflow,
was found in the way the rsyslog imfile module processed text files
containing long lines. An attacker could use this flaw to crash the
rsyslogd daemon or, possibly, execute arbitrary code with the
privileges of rsyslogd, if they are able to cause a long line to be
written to a log file that rsyslogd monitors with imfile. The imfile
module is not enabled by default. (CVE-2011-4623)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-105.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update rsyslog' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"rsyslog-5.8.10-2.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rsyslog-debuginfo-5.8.10-2.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rsyslog-gnutls-5.8.10-2.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rsyslog-gssapi-5.8.10-2.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rsyslog-mysql-5.8.10-2.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rsyslog-pgsql-5.8.10-2.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rsyslog-snmp-5.8.10-2.17.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsyslog / rsyslog-debuginfo / rsyslog-gnutls / rsyslog-gssapi / etc");
}
