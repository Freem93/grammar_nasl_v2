#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(64957);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/03/16 02:58:07 $");

  script_cve_id("CVE-2011-1398", "CVE-2012-0831", "CVE-2012-2688");

  script_name(english:"Scientific Linux Security Update : php on SL6.x i386/x86_64");
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
"It was found that PHP did not check for carriage returns in HTTP
headers, allowing intended HTTP response splitting protections to be
bypassed. Depending on the web browser the victim is using, a remote
attacker could use this flaw to perform HTTP response splitting
attacks. (CVE-2011-1398)

An integer signedness issue, leading to a heap-based buffer underflow,
was found in the PHP scandir() function. If a remote attacker could
upload an excessively large number of files to a directory the
scandir() function runs on, it could cause the PHP interpreter to
crash or, possibly, execute arbitrary code. (CVE-2012-2688)

It was found that PHP did not correctly handle the magic_quotes_gpc
configuration directive. This could result in magic_quotes_gpc input
escaping not being applied in all cases, possibly making it easier for
a remote attacker to perform SQL injection attacks. (CVE-2012-0831)

After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=3911
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00922e22"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"php-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-bcmath-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-cli-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-common-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-dba-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-debuginfo-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-devel-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-embedded-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-enchant-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-fpm-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-gd-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-imap-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-intl-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-ldap-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-mbstring-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-mysql-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-odbc-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-pdo-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-pgsql-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-process-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-pspell-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-recode-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-snmp-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-soap-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-tidy-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-xml-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-xmlrpc-5.3.3-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-zts-5.3.3-22.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
