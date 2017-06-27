#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(92997);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/24 13:46:12 $");

  script_cve_id("CVE-2016-5385");

  script_name(english:"Scientific Linux Security Update : php on SL7.x x86_64 (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

  - It was discovered that PHP did not properly protect
    against the HTTP_PROXY variable name clash. A remote
    attacker could possibly use this flaw to redirect HTTP
    requests performed by a PHP script to an attacker-
    controlled proxy via a malicious HTTP request.
    (CVE-2016-5385)

Bug Fix(es) :

  - Previously, an incorrect logic in the SAPI header
    callback routine caused that the callback counter was
    not incremented. Consequently, when a script included a
    header callback, it could terminate unexpectedly with a
    segmentation fault. With this update, the callback
    counter is properly managed, and scripts with a header
    callback implementation work as expected."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1608&L=scientific-linux-errata&F=&S=&P=5188
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a02910d0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-bcmath-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-cli-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-common-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-dba-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-debuginfo-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-devel-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-embedded-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-enchant-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-fpm-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-gd-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-intl-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-ldap-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-mbstring-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-mysql-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-mysqlnd-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-odbc-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-pdo-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-pgsql-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-process-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-pspell-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-recode-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-snmp-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-soap-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-xml-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-xmlrpc-5.4.16-36.3.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
