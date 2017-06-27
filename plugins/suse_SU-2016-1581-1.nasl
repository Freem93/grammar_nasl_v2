#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1581-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(91665);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/27 20:24:08 $");

  script_cve_id("CVE-2014-9767", "CVE-2015-4116", "CVE-2015-7803", "CVE-2015-8835", "CVE-2015-8838", "CVE-2015-8866", "CVE-2015-8867", "CVE-2015-8873", "CVE-2015-8874", "CVE-2015-8879", "CVE-2016-2554", "CVE-2016-3141", "CVE-2016-3142", "CVE-2016-3185", "CVE-2016-4070", "CVE-2016-4073", "CVE-2016-4342", "CVE-2016-4346", "CVE-2016-4537", "CVE-2016-4538", "CVE-2016-4539", "CVE-2016-4540", "CVE-2016-4541", "CVE-2016-4542", "CVE-2016-4543", "CVE-2016-4544", "CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5095", "CVE-2016-5096", "CVE-2016-5114");
  script_osvdb_id(122735, 125852, 125855, 125857, 125858, 125859, 127122, 128347, 132662, 134031, 134034, 135224, 135225, 135227, 136485, 136486, 137454, 137753, 137758, 137781, 137782, 137783, 137784, 138996, 138997, 139005);

  script_name(english:"SUSE SLES11 Security Update : php53 (SUSE-SU-2016:1581-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for php53 fixes the following issues :

  - CVE-2016-5093: A get_icu_value_internal out-of-bounds
    read could crash the php interpreter (bsc#982010)

  - CVE-2016-5094,CVE-2016-5095: Don't allow creating
    strings with lengths outside int range, avoids overflows
    (bsc#982011,bsc#982012)

  - CVE-2016-5096: A int/size_t confusion in fread could
    corrupt memory (bsc#982013)

  - CVE-2016-5114: A fpm_log.c memory leak and buffer
    overflow could leak information out of the php process
    or overwrite a buffer by 1 byte (bsc#982162)

  - CVE-2016-4346: A heap overflow was fixed in
    ext/standard/string.c (bsc#977994)

  - CVE-2016-4342: A heap corruption was fixed in
    tar/zip/phar parser (bsc#977991)

  - CVE-2016-4537, CVE-2016-4538: bcpowmod accepted negative
    scale causing heap buffer overflow corrupting _one_
    definition (bsc#978827)

  - CVE-2016-4539: Malformed input causes segmentation fault
    in xml_parse_into_struct() function (bsc#978828)

  - CVE-2016-4540, CVE-2016-4541: Out-of-bounds memory read
    in zif_grapheme_stripos when given negative offset
    (bsc#978829)

  - CVE-2016-4542, CVE-2016-4543, CVE-2016-4544:
    Out-of-bounds heap memory read in exif_read_data()
    caused by malformed input (bsc#978830)

  - CVE-2015-4116: Use-after-free vulnerability in the
    spl_ptr_heap_insert function (bsc#980366)

  - CVE-2015-8873: Stack consumption vulnerability in
    Zend/zend_exceptions.c (bsc#980373)

  - CVE-2015-8874: Stack consumption vulnerability in GD
    (bsc#980375)

  - CVE-2015-8879: odbc_bindcols function in
    ext/odbc/php_odbc.c mishandles driver behavior for
    SQL_WVARCHAR (bsc#981050)

Also fixed previously on SUSE Linux Enterprise 11 SP4, but not yet
shipped to SUSE Linux Enterprise Server 11 SP3 LTSS :

  - CVE-2015-8838: mysqlnd was vulnerable to BACKRONYM
    (bnc#973792).

  - CVE-2015-8835: SoapClient s_call method suffered from a
    type confusion issue that could have lead to crashes
    [bsc#973351]

  - CVE-2016-2554: A NULL pointer dereference in
    phar_get_fp_offset could lead to crashes. [bsc#968284]

  - CVE-2015-7803: A Stack overflow vulnerability when
    decompressing tar phar archives could potentially lead
    to code execution. [bsc#949961]

  - CVE-2016-3141: A use-after-free / double-free in the
    WDDX deserialization could lead to crashes or potential
    code execution. [bsc#969821]

  - CVE-2016-3142: An Out-of-bounds read in
    phar_parse_zipfile() could lead to crashes. [bsc#971912]

  - CVE-2014-9767: A directory traversal when extracting zip
    files was fixed that could lead to overwritten files.
    [bsc#971612]

  - CVE-2016-3185: A type confusion vulnerability in
    make_http_soap_request() could lead to crashes or
    potentially code execution. [bsc#971611]

  - CVE-2016-4073: A remote attacker could have caused
    denial of service, or possibly execute arbitrary code,
    due to incorrect handling of string length calculations
    in mb_strcut() (bsc#977003)

  - CVE-2015-8867: The PHP function
    openssl_random_pseudo_bytes() did not return
    cryptographically secure random bytes (bsc#977005)

  - CVE-2016-4070: The libxml_disable_entity_loader()
    setting was shared between threads, which could have
    resulted in XML external entity injection and entity
    expansion issues (bsc#976997)

  - CVE-2015-8866: A remote attacker could have caused
    denial of service due to incorrect handling of large
    strings in php_raw_url_encode() (bsc#976996)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4116.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7803.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8838.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8866.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8867.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8873.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8874.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8879.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3141.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3142.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4070.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4073.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4342.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4346.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4538.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4539.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4540.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4541.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4542.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4543.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4544.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5096.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5114.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161581-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfe93b5c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5 :

zypper in -t patch sleclo50sp3-php53-12611=1

SUSE Manager Proxy 2.1 :

zypper in -t patch slemap21-php53-12611=1

SUSE Manager 2.1 :

zypper in -t patch sleman21-php53-12611=1

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-php53-12611=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-php53-12611=1

SUSE Linux Enterprise Server 11-SP3-LTSS :

zypper in -t patch slessp3-php53-12611=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-php53-12611=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-php53-12611=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:"4", reference:"apache2-mod_php53-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-bcmath-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-bz2-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-calendar-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-ctype-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-curl-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-dba-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-dom-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-exif-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-fastcgi-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-fileinfo-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-ftp-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-gd-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-gettext-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-gmp-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-iconv-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-intl-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-json-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-ldap-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-mbstring-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-mcrypt-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-mysql-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-odbc-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-openssl-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pcntl-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pdo-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pear-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pgsql-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pspell-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-shmop-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-snmp-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-soap-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-suhosin-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-sysvmsg-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-sysvsem-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-sysvshm-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-tokenizer-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-wddx-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-xmlreader-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-xmlrpc-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-xmlwriter-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-xsl-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-zip-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-zlib-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"apache2-mod_php53-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-bcmath-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-bz2-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-calendar-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-ctype-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-curl-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-dba-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-dom-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-exif-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-fastcgi-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-fileinfo-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-ftp-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-gd-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-gettext-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-gmp-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-iconv-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-intl-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-json-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-ldap-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-mbstring-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-mcrypt-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-mysql-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-odbc-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-openssl-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pcntl-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pdo-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pear-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pgsql-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-pspell-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-shmop-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-snmp-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-soap-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-suhosin-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-sysvmsg-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-sysvsem-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-sysvshm-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-tokenizer-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-wddx-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-xmlreader-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-xmlrpc-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-xmlwriter-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-xsl-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-zip-5.3.17-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"php53-zlib-5.3.17-71.1")) flag++;


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
