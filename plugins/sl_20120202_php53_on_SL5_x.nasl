#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61237);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2012-0830");

  script_name(english:"Scientific Linux Security Update : php53 on SL5.x i386/x86_64");
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
"PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

It was discovered that the fix for CVE-2011-4885 (released via in a
previous update for php53) introduced an uninitialized memory use
flaw. A remote attacker could send a specially crafted HTTP request to
cause the PHP interpreter to crash or, possibly, execute arbitrary
code. (CVE-2012-0830)

All php53 users should upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
updated packages, the httpd daemon must be restarted for the update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=673
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edd36e6d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"php53-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-bcmath-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-cli-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-common-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-dba-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-debuginfo-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-devel-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-gd-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-imap-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-intl-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-ldap-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-mbstring-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-mysql-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-odbc-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-pdo-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-pgsql-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-process-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-pspell-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-snmp-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-soap-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-xml-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"php53-xmlrpc-5.3.3-1.el5_7.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
