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
  script_id(53282);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/25 23:41:51 $");

  script_cve_id("CVE-2010-4150", "CVE-2010-4645", "CVE-2010-4697", "CVE-2010-4698", "CVE-2010-4699", "CVE-2011-0708", "CVE-2011-0752", "CVE-2011-0753", "CVE-2011-0755");

  script_name(english:"SuSE 11.1 Security Update : PHP5 (SAT Patch Number 4133)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:"PHP5 was updated to fix several security issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=656523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=666512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=671710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4150.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4645.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4697.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4698.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4699.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0708.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0752.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0753.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0755.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 4133.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLES11", sp:1, reference:"apache2-mod_php5-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-bcmath-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-bz2-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-calendar-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-ctype-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-curl-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-dba-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-dbase-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-dom-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-exif-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-fastcgi-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-ftp-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-gd-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-gettext-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-gmp-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-hash-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-iconv-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-json-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-ldap-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-mbstring-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-mcrypt-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-mysql-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-odbc-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-openssl-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-pcntl-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-pdo-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-pear-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-pgsql-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-pspell-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-shmop-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-snmp-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-soap-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-suhosin-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-sysvmsg-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-sysvsem-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-sysvshm-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-tokenizer-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-wddx-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-xmlreader-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-xmlrpc-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-xmlwriter-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-xsl-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-zip-5.2.14-0.7.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-zlib-5.2.14-0.7.22.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
