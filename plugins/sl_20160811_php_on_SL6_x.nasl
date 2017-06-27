#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(92965);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/24 13:46:12 $");

  script_cve_id("CVE-2016-5385");

  script_name(english:"Scientific Linux Security Update : php on SL6.x i386/x86_64 (httpoxy)");
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
    (CVE-2016-5385)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1608&L=scientific-linux-errata&F=&S=&P=4870
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c92ada36"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/15");
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
if (rpm_check(release:"SL6", reference:"php-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-bcmath-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-cli-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-common-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-dba-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-debuginfo-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-devel-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-embedded-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-enchant-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-fpm-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-gd-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-imap-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-intl-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-ldap-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-mbstring-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-mysql-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-odbc-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-pdo-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-pgsql-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-process-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-pspell-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-recode-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-snmp-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-soap-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-tidy-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-xml-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-xmlrpc-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"php-zts-5.3.3-48.el6_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
