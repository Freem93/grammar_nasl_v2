#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:209. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(83101);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2015/10/05 13:44:22 $");

  script_cve_id("CVE-2015-2783", "CVE-2015-3329", "CVE-2015-3330");
  script_xref(name:"MDVSA", value:"2015:209");

  script_name(english:"Mandriva Linux Security Advisory : php (MDVSA-2015:209)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages fix security vulnerabilities :

Buffer Over-read in unserialize when parsing Phar (CVE-2015-2783).

Buffer Overflow when parsing tar/zip/phar in phar_set_inode
(CVE-2015-3329).

Potential remote code execution with apache 2.4 apache2handler
(CVE-2015-3330).

PHP has been updated to version 5.5.24, which fixes these issues and
other bugs.

Additionally the timezonedb packages has been upgraded to the latest
version and the PECL packages which requires so has been rebuilt for
php-5.5.24."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0169.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-apc-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-hash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mysqli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_dblib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sybase_ct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-timezonedb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"apache-mod_php-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64php5_common5-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-apc-3.1.15-1.18.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-apc-admin-3.1.15-1.18.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-bcmath-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-bz2-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-calendar-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-cgi-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-cli-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-ctype-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-curl-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-dba-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-devel-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-doc-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-dom-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-enchant-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-exif-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-fileinfo-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-filter-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-fpm-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-ftp-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-gd-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-gettext-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-gmp-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-hash-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-iconv-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-imap-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-ini-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-intl-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-json-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-ldap-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-mbstring-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-mcrypt-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-mssql-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-mysql-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-mysqli-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-mysqlnd-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-odbc-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-opcache-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-openssl-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-pcntl-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-pdo-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-pdo_dblib-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-pdo_mysql-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-pdo_odbc-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-pdo_pgsql-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-pdo_sqlite-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-pgsql-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-phar-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-posix-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-readline-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-recode-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-session-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-shmop-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-snmp-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-soap-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-sockets-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-sqlite3-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-sybase_ct-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-sysvmsg-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-sysvsem-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-sysvshm-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-tidy-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-timezonedb-2015.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-tokenizer-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-wddx-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-xml-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-xmlreader-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-xmlrpc-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-xmlwriter-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-xsl-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-zip-5.5.24-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-zlib-5.5.24-1.mbs1")) flag++;

if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"apache-mod_php-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64php5_common5-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-bcmath-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-bz2-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-calendar-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-cgi-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-cli-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-ctype-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-curl-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-dba-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-devel-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-doc-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-dom-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-enchant-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-exif-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-fileinfo-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-filter-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-fpm-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-ftp-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-gd-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-gettext-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-gmp-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-hash-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-iconv-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-imap-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-ini-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-interbase-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-intl-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-json-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-ldap-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-mbstring-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-mcrypt-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-mssql-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-mysql-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-mysqli-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-mysqlnd-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-odbc-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-opcache-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-openssl-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pcntl-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo_dblib-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo_firebird-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo_mysql-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo_odbc-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo_pgsql-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo_sqlite-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pgsql-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-phar-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-posix-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-readline-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-recode-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-session-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-shmop-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-snmp-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-soap-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-sockets-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-sqlite3-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-sybase_ct-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-sysvmsg-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-sysvsem-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-sysvshm-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-tidy-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-timezonedb-2015.4-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-tokenizer-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-wddx-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-xml-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-xmlreader-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-xmlrpc-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-xmlwriter-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-xsl-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-zip-5.5.24-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-zlib-5.5.24-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
