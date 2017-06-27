#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69294);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/25 23:41:51 $");

  script_cve_id("CVE-2013-1635", "CVE-2013-1643", "CVE-2013-4113", "CVE-2013-4635");

  script_name(english:"SuSE 11.2 Security Update : PHP5 (SAT Patch Number 8086)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security issues have been fixed :

  - (bnc#828020):. (CVE-2013-4635)

  - Integer overflow in SdnToJewish()

  - (bnc#807707):. (CVE-2013-1635 / CVE-2013-1643)

  - reading system files via untrusted SOAP input

  - soap.wsdl_cache_dir function did not honour PHP
    open_basedir

  - (bnc#829207):. (CVE-2013-4113)

  - heap corruption due to badly formed xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=783239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1635.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1643.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4113.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4635.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 8086.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-dbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-hash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php5-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLES11", sp:2, reference:"apache2-mod_php5-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-bcmath-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-bz2-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-calendar-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-ctype-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-curl-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-dba-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-dbase-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-dom-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-exif-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-fastcgi-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-ftp-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-gd-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-gettext-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-gmp-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-hash-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-iconv-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-json-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-ldap-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-mbstring-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-mcrypt-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-mysql-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-odbc-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-openssl-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-pcntl-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-pdo-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-pear-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-pgsql-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-pspell-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-shmop-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-snmp-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-soap-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-suhosin-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-sysvmsg-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-sysvsem-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-sysvshm-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-tokenizer-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-wddx-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-xmlreader-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-xmlrpc-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-xmlwriter-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-xsl-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-zip-5.2.14-0.7.30.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php5-zlib-5.2.14-0.7.30.48.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
