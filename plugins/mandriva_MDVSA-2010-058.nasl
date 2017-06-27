#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:058. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(45029);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/17 17:02:54 $");

  script_cve_id("CVE-2010-1128", "CVE-2010-1129", "CVE-2010-1130");
  script_bugtraq_id(38182, 38430, 38431);
  script_xref(name:"MDVSA", value:"2010:058");

  script_name(english:"Mandriva Linux Security Advisory : php (MDVSA-2010:058)");
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
"Multiple vulnerabilities has been found and corrected in php :

  - Improved LCG entropy. (Rasmus, Samy Kamkar)
    (CVE-2010-1128)

    - Fixed safe_mode validation inside tempnam() when the
      directory path does not end with a /). (Martin Jansen)
      (CVE-2010-1129)

  - Fixed a possible open_basedir/safe_mode bypass in the
    session extension identified by Grzegorz Stachowiak.
    (Ilia) (CVE-2010-1130)

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers.

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.2.13"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.3.2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-dbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-hash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mhash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mime_magic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mysqli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_dblib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-simplexml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sybase_ct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64php5_common5-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libphp5_common5-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-bcmath-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-bz2-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-calendar-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-cgi-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-cli-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-ctype-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-curl-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-dba-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-dbase-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-devel-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-dom-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-exif-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-fcgi-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-filter-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-ftp-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-gd-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-gettext-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-gmp-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-hash-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-iconv-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-imap-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-json-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-ldap-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-mbstring-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-mcrypt-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-mhash-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-mime_magic-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-ming-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-mssql-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-mysql-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-mysqli-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-ncurses-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-odbc-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-openssl-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-pcntl-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-pdo-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-pdo_dblib-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-pdo_mysql-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-pdo_odbc-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-pdo_pgsql-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-pdo_sqlite-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-pgsql-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-posix-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-pspell-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-readline-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-recode-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-session-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-shmop-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-simplexml-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-snmp-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-soap-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-sockets-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-sqlite-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-sysvmsg-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-sysvsem-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-sysvshm-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-tidy-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-tokenizer-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-wddx-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-xml-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-xmlreader-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-xmlrpc-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-xmlwriter-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-xsl-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-zlib-5.2.4-3.9mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64php5_common5-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libphp5_common5-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-bcmath-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-bz2-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-calendar-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-cgi-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-cli-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-ctype-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-curl-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-dba-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-dbase-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-devel-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-dom-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-exif-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-fcgi-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-filter-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-ftp-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-gd-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-gettext-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-gmp-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-hash-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-iconv-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-imap-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-json-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-ldap-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-mbstring-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-mcrypt-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-mhash-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-mime_magic-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-ming-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-mssql-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-mysql-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-mysqli-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-ncurses-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-odbc-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-openssl-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-pcntl-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-pdo-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-pdo_dblib-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-pdo_mysql-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-pdo_odbc-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-pdo_pgsql-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-pdo_sqlite-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-pgsql-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-posix-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-pspell-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-readline-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-recode-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-session-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-shmop-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-snmp-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-soap-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-sockets-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-sqlite-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-sybase-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-sysvmsg-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-sysvsem-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-sysvshm-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-tidy-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-tokenizer-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-wddx-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-xml-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-xmlreader-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-xmlrpc-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-xmlwriter-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-xsl-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"php-zlib-5.2.6-18.13mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64php5_common5-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libphp5_common5-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-bcmath-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-bz2-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-calendar-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-cgi-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-cli-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-ctype-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-curl-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-dba-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-dbase-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-devel-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-dom-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-exif-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-fcgi-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-filter-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-ftp-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-gd-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-gettext-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-gmp-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-hash-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-iconv-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-imap-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-json-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-ldap-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-mbstring-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-mcrypt-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-mhash-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-mime_magic-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-ming-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-mssql-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-mysql-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-mysqli-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-ncurses-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-odbc-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-openssl-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-pcntl-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-pdo-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-pdo_dblib-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-pdo_mysql-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-pdo_odbc-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-pdo_pgsql-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-pdo_sqlite-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-pgsql-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-posix-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-pspell-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-readline-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-recode-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-session-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-shmop-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-snmp-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-soap-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-sockets-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-sqlite-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-sybase-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-sysvmsg-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-sysvsem-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-sysvshm-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-tidy-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-tokenizer-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-wddx-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-xml-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-xmlreader-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-xmlrpc-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-xmlwriter-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-xsl-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-zip-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"php-zlib-5.2.11-0.5mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64php5_common5-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libphp5_common5-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-bcmath-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-bz2-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-calendar-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-cgi-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-cli-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-ctype-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-curl-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-dba-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-devel-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-doc-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-dom-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-enchant-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-exif-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-fileinfo-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-filter-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-ftp-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-gd-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-gettext-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-gmp-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-hash-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-iconv-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-imap-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-intl-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-json-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-ldap-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-mbstring-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-mcrypt-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-mssql-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-mysql-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-mysqli-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-odbc-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-openssl-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-pcntl-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-pdo-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-pdo_dblib-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-pdo_mysql-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-pdo_odbc-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-pdo_pgsql-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-pdo_sqlite-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-pgsql-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-posix-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-pspell-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-readline-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-recode-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-session-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-shmop-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-snmp-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-soap-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-sockets-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-sqlite3-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-sybase_ct-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-sysvmsg-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-sysvsem-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-sysvshm-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-tidy-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-tokenizer-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-wddx-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-xml-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-xmlreader-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-xmlrpc-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-xmlwriter-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-xsl-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-zip-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"php-zlib-5.3.1-0.3mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
