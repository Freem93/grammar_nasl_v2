#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-386.
#

include("compat.inc");

if (description)
{
  script_id(78329);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2014-3430");
  script_xref(name:"ALAS", value:"2014-386");

  script_name(english:"Amazon Linux AMI : dovecot (ALAS-2014-386)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dovecot 1.1 before 2.2.13 and dovecot-ee before 2.1.7.7 and 2.2.x
before 2.2.12.12 does not properly close old connections, which allows
remote attackers to cause a denial of service (resource consumption)
via an incomplete SSL/TLS handshake for an IMAP/POP3 connection."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-386.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update dovecot' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dovecot-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dovecot-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dovecot-pigeonhole");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"dovecot-2.0.9-7.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dovecot-debuginfo-2.0.9-7.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dovecot-devel-2.0.9-7.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dovecot-mysql-2.0.9-7.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dovecot-pgsql-2.0.9-7.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dovecot-pigeonhole-2.0.9-7.14.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot / dovecot-debuginfo / dovecot-devel / dovecot-mysql / etc");
}
