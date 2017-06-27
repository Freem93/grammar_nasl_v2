#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1818-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86616);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2015-6831", "CVE-2015-6833", "CVE-2015-6836", "CVE-2015-6837", "CVE-2015-6838");
  script_osvdb_id(125849, 125850, 125851, 125854, 126952, 126989);

  script_name(english:"SUSE SLES11 Security Update : php53 (SUSE-SU-2015:1818-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of PHP5 brings several security fixes.

Security fixes :

  - CVE-2015-6831: A use after free vulnerability in
    unserialize() has been fixed which could be used to
    crash php or potentially execute code. [bnc#942291]
    [bnc#942294] [bnc#942295]

  - CVE-2015-6836: A SOAP serialize_function_call() type
    confusion leading to remote code execution problem was
    fixed. [bnc#945428]

  - CVE-2015-6837 CVE-2015-6838: Two NULL pointer
    dereferences in the XSLTProcessor class were fixed.
    [bnc#945412]

It also includes a bugfix for the odbc module :

  - compare with SQL_NULL_DATA correctly [bnc#935074]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6831.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6833.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6837.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6838.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151818-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db1bd10e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-php53-12163=1

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-php53-12163=1

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-php53-12163=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-php53-12163=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-php53-12163=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-php53-12163=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-php53-12163=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"apache2-mod_php53-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-bcmath-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-bz2-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-calendar-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-ctype-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-curl-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-dba-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-dom-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-exif-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-fastcgi-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-fileinfo-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-ftp-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-gd-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-gettext-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-gmp-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-iconv-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-intl-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-json-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-ldap-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-mbstring-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-mcrypt-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-mysql-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-odbc-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-openssl-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pcntl-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pdo-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pear-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pgsql-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pspell-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-shmop-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-snmp-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-soap-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-suhosin-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-sysvmsg-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-sysvsem-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-sysvshm-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-tokenizer-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-wddx-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-xmlreader-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-xmlrpc-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-xmlwriter-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-xsl-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-zip-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-zlib-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"apache2-mod_php53-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-bcmath-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-bz2-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-calendar-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-ctype-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-curl-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-dba-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-dom-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-exif-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-fastcgi-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-fileinfo-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-ftp-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-gd-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-gettext-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-gmp-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-iconv-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-intl-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-json-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-ldap-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-mbstring-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-mcrypt-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-mysql-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-odbc-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-openssl-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pcntl-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pdo-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pear-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pgsql-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pspell-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-shmop-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-snmp-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-soap-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-suhosin-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-sysvmsg-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-sysvsem-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-sysvshm-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-tokenizer-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-wddx-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-xmlreader-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-xmlrpc-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-xmlwriter-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-xsl-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-zip-5.3.17-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-zlib-5.3.17-48.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php53");
}
