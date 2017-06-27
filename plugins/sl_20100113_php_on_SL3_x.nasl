#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60723);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-2687", "CVE-2009-3291", "CVE-2009-3292", "CVE-2009-3546", "CVE-2009-4017", "CVE-2009-4142");

  script_name(english:"Scientific Linux Security Update : php on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"CVE-2009-2687 php: exif_read_data crash on corrupted JPEG files

CVE-2009-3292 php: exif extension: Multiple missing sanity checks in
EXIF file processing

CVE-2009-3291 php: openssl extension: Incorrect verification of SSL
certificate with NUL in name

CVE-2009-3546 gd: insufficient input validation in _gdGetColors()

CVE-2009-4017 PHP: resource exhaustion attack via upload requests with
lots of files

CVE-2009-4142 php: htmlspecialchars() insufficient checking of input
for multi-byte encodings

Multiple missing input sanitization flaws were discovered in PHP's
exif extension. A specially crafted image file could cause the PHP
interpreter to crash or, possibly, disclose portions of its memory
when a PHP script tried to extract Exchangeable image file format
(Exif) metadata from the image file. (CVE-2009-2687, CVE-2009-3292)

A missing input sanitization flaw, leading to a buffer overflow, was
discovered in PHP's gd library. A specially crafted GD image file
could cause the PHP interpreter to crash or, possibly, execute
arbitrary code when opened. (CVE-2009-3546)

It was discovered that PHP did not limit the maximum number of files
that can be uploaded in one request. A remote attacker could use this
flaw to instigate a denial of service by causing the PHP interpreter
to use lots of system resources dealing with requests containing large
amounts of files to be uploaded. This vulnerability depends on file
uploads being enabled (which it is, in the default PHP configuration).
(CVE-2009-4017)

Note: This update introduces a new configuration option,
max_file_uploads, used for limiting the number of files that can be
uploaded in one request. By default, the limit is 20 files per
request.

It was discovered that PHP was affected by the previously published
'null prefix attack', caused by incorrect handling of NUL characters
in X.509 certificates. If an attacker is able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority, the attacker could use the certificate during a
man-in-the-middle attack and potentially confuse PHP into accepting it
by mistake. (CVE-2009-3291)

It was discovered that PHP's htmlspecialchars() function did not
properly recognize partial multi-byte sequences for some multi-byte
encodings, sending them to output without them being escaped. An
attacker could use this flaw to perform a cross-site scripting attack.
(CVE-2009-4142)

After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1001&L=scientific-linux-errata&T=0&P=1199
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4017a73e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"php-4.3.2-54.ent")) flag++;
if (rpm_check(release:"SL3", reference:"php-devel-4.3.2-54.ent")) flag++;
if (rpm_check(release:"SL3", reference:"php-imap-4.3.2-54.ent")) flag++;
if (rpm_check(release:"SL3", reference:"php-ldap-4.3.2-54.ent")) flag++;
if (rpm_check(release:"SL3", reference:"php-mysql-4.3.2-54.ent")) flag++;
if (rpm_check(release:"SL3", reference:"php-odbc-4.3.2-54.ent")) flag++;
if (rpm_check(release:"SL3", reference:"php-pgsql-4.3.2-54.ent")) flag++;

if (rpm_check(release:"SL4", reference:"php-4.3.9-3.29")) flag++;
if (rpm_check(release:"SL4", reference:"php-devel-4.3.9-3.29")) flag++;
if (rpm_check(release:"SL4", reference:"php-domxml-4.3.9-3.29")) flag++;
if (rpm_check(release:"SL4", reference:"php-gd-4.3.9-3.29")) flag++;
if (rpm_check(release:"SL4", reference:"php-imap-4.3.9-3.29")) flag++;
if (rpm_check(release:"SL4", reference:"php-ldap-4.3.9-3.29")) flag++;
if (rpm_check(release:"SL4", reference:"php-mbstring-4.3.9-3.29")) flag++;
if (rpm_check(release:"SL4", reference:"php-mysql-4.3.9-3.29")) flag++;
if (rpm_check(release:"SL4", reference:"php-ncurses-4.3.9-3.29")) flag++;
if (rpm_check(release:"SL4", reference:"php-odbc-4.3.9-3.29")) flag++;
if (rpm_check(release:"SL4", reference:"php-pear-4.3.9-3.29")) flag++;
if (rpm_check(release:"SL4", reference:"php-pgsql-4.3.9-3.29")) flag++;
if (rpm_check(release:"SL4", reference:"php-snmp-4.3.9-3.29")) flag++;
if (rpm_check(release:"SL4", reference:"php-xmlrpc-4.3.9-3.29")) flag++;

if (rpm_check(release:"SL5", reference:"php-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-bcmath-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-cli-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-common-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-dba-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-devel-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-gd-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-imap-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-ldap-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-mbstring-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-mysql-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-ncurses-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-odbc-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-pdo-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-pgsql-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-snmp-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-soap-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-xml-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"SL5", reference:"php-xmlrpc-5.1.6-24.el5_4.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
