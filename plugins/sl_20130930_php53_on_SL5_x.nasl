#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(70389);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/03/02 00:50:39 $");

  script_cve_id("CVE-2006-7243", "CVE-2011-1398", "CVE-2012-0831", "CVE-2012-2688", "CVE-2013-1643", "CVE-2013-4248");

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
"It was found that PHP did not properly handle file names with a NULL
character. A remote attacker could possibly use this flaw to make a
PHP script access unexpected files and bypass intended file system
access restrictions. (CVE-2006-7243)

It was found that PHP did not check for carriage returns in HTTP
headers, allowing intended HTTP response splitting protections to be
bypassed. Depending on the web browser the victim is using, a remote
attacker could use this flaw to perform HTTP response splitting
attacks. (CVE-2011-1398)

A flaw was found in PHP's SSL client's hostname identity check when
handling certificates that contain hostnames with NULL bytes. If an
attacker was able to get a carefully crafted certificate signed by a
trusted Certificate Authority, the attacker could use the certificate
to conduct man-in-the-middle attacks to spoof SSL servers.
(CVE-2013-4248)

An integer signedness issue, leading to a heap-based buffer underflow,
was found in the PHP scandir() function. If a remote attacker could
upload an excessively large number of files to a directory the
scandir() function runs on, it could cause the PHP interpreter to
crash or, possibly, execute arbitrary code. (CVE-2012-2688)

It was found that PHP did not correctly handle the magic_quotes_gpc
configuration directive. This could result in magic_quotes_gpc input
escaping not being applied in all cases, possibly making it easier for
a remote attacker to perform SQL injection attacks. (CVE-2012-0831)

It was found that the PHP SOAP parser allowed the expansion of
external XML entities during SOAP message parsing. A remote attacker
could possibly use this flaw to read arbitrary files that are
accessible to a PHP application using a SOAP extension.
(CVE-2013-1643)

After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1310&L=scientific-linux-errata&T=0&P=809
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48631a87"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"php53-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-bcmath-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-cli-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-common-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-dba-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-debuginfo-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-devel-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-gd-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-imap-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-intl-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-ldap-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-mbstring-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-mysql-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-odbc-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-pdo-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-pgsql-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-process-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-pspell-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-snmp-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-soap-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-xml-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-xmlrpc-5.3.3-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"unixODBC-2.2.11-10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"unixODBC-devel-2.2.11-10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"unixODBC-kde-2.2.11-10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"unixODBC-libs-2.2.11-10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"unixODBC64-2.2.14-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"unixODBC64-devel-2.2.14-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"unixODBC64-libs-2.2.14-3.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
