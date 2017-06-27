#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0868-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83630);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2014-2497", "CVE-2014-4049");
  script_bugtraq_id(66233, 68007);

  script_name(english:"SUSE SLES11 Security Update : PHP5 (SUSE-SU-2014:0868-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PHP5 has been updated to fix two security vulnerabilities :

  - Heap-based buffer overflow in DNS TXT record parsing
    (CVE-2014-4049)

  - NULL pointer dereference in GD XPM decoder
    (CVE-2014-2497)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=5a6e6d1523035a22186fef4bad38da0d
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc8643d8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2497.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/868624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/882992"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140868-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6bd146b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP2 LTSS :

zypper in -t patch slessp2-apache2-mod_php5-9409

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-hash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^2$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", reference:"apache2-mod_php5-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-bcmath-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-bz2-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-calendar-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-ctype-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-curl-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-dba-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-dbase-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-dom-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-exif-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-fastcgi-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-ftp-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-gd-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-gettext-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-gmp-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-hash-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-iconv-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-json-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-ldap-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-mbstring-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-mcrypt-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-mysql-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-odbc-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-openssl-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-pcntl-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-pdo-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-pear-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-pgsql-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-pspell-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-shmop-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-snmp-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-soap-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-suhosin-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-sysvmsg-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-sysvsem-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-sysvshm-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-tokenizer-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-wddx-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-xmlreader-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-xmlrpc-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-xmlwriter-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-xsl-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-zip-5.2.14-0.7.30.54.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-zlib-5.2.14-0.7.30.54.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHP5");
}
