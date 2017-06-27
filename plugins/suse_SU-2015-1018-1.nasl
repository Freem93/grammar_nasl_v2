#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1018-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84082);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2015/10/05 13:44:23 $");

  script_cve_id("CVE-2014-9705", "CVE-2014-9709", "CVE-2015-2301", "CVE-2015-2305", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3329", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4026");
  script_bugtraq_id(72611, 73031, 73037, 73306, 73431, 74239, 74240, 74700, 74902, 74903, 75056);
  script_osvdb_id(117469, 118433, 118582, 119650, 119774, 120925, 120938, 122125, 122126, 122127, 122261);

  script_name(english:"SUSE SLES11 Security Update : php53 (SUSE-SU-2015:1018-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PHP 5.3 was updated to fix multiple security issues :

bnc#931776: pcntl_exec() does not check path validity (CVE-2015-4026)

bnc#931772: overflow in ftp_genlist() resulting in heap overflow
(CVE-2015-4022)

bnc#931769: memory corruption in phar_parse_tarfile when entry
filename starts with NULL (CVE-2015-4021)

bnc#931421: multipart/form-data remote denial-of-service vulnerability
(CVE-2015-4024)

bnc#928511: buffer over-read in unserialize when parsing Phar
(CVE-2015-2783)

bnc#928506: buffer over flow when parsing tar/zip/phar in
phar_set_inode() (CVE-2015-3329)

bnc#925109: SoapClient's __call() type confusion through unserialize()

bnc#924972: use-after-free vulnerability in the process_nested_data
function (CVE-2015-2787)

bnc#923946: embedded gd copy: buffer read overflow in gd_gif_in.c
(CVE-2014-9709)

bnc#922452: built-in regular expression (regex) library contains a
heap overflow vulnerability (CVE-2015-2305)

bnc#922451: heap buffer overflow in enchant_broker_request_dict()
(CVE-2014-9705)

bnc#922022: php's built-in regular expression (regex) library contains
a heap overflow vulnerability (CVE-2015-2301)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/923946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931776"
  );
  # https://download.suse.com/patch/finder/?keywords=50901ea397c43cdc72e7b8b864450cd7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d03cc6d1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9705.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9709.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2301.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2305.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2783.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2787.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3329.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4026.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151018-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48073445"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11 SP3 :

zypper in -t patch sdksp3-apache2-mod_php53=10716

SUSE Linux Enterprise Server 11 SP3 for VMware :

zypper in -t patch slessp3-apache2-mod_php53=10716

SUSE Linux Enterprise Server 11 SP3 :

zypper in -t patch slessp3-apache2-mod_php53=10716

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/10");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", reference:"apache2-mod_php53-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-bcmath-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-bz2-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-calendar-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-ctype-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-curl-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-dba-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-dom-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-exif-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-fastcgi-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-fileinfo-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-ftp-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-gd-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-gettext-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-gmp-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-iconv-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-intl-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-json-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-ldap-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-mbstring-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-mcrypt-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-mysql-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-odbc-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-openssl-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pcntl-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pdo-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pear-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pgsql-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pspell-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-shmop-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-snmp-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-soap-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-suhosin-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-sysvmsg-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-sysvsem-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-sysvshm-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-tokenizer-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-wddx-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-xmlreader-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-xmlrpc-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-xmlwriter-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-xsl-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-zip-5.3.17-0.41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-zlib-5.3.17-0.41.1")) flag++;


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
