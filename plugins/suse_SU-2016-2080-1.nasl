#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2080-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93293);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2015-8935", "CVE-2016-5399", "CVE-2016-5766", "CVE-2016-5767", "CVE-2016-5769", "CVE-2016-5772", "CVE-2016-6288", "CVE-2016-6289", "CVE-2016-6290", "CVE-2016-6291", "CVE-2016-6296", "CVE-2016-6297");
  script_osvdb_id(140308, 140384, 140387, 140388, 140390, 141944, 141945, 141946, 141957, 141958, 142018, 142133);

  script_name(english:"SUSE SLES11 Security Update : php5 (SUSE-SU-2016:2080-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"php5 was updated to fix the following security issues :

  - CVE-2016-6297: Stack-based buffer overflow vulnerability
    in php_stream_zip_opener (bsc#991426).

  - CVE-2016-6291: Out-of-bounds access in
    exif_process_IFD_in_MAKERNOTE (bsc#991427).

  - CVE-2016-6289: Integer overflow leads to buffer overflow
    in virtual_file_ex (bsc#991428).

  - CVE-2016-6290: Use after free in unserialize() with
    Unexpected Session Deserialization (bsc#991429).

  - CVE-2016-5399: Improper error handling in bzread()
    (bsc#991430).

  - CVE-2016-6288: Buffer over-read in php_url_parse_ex
    (bsc#991433).

  - CVE-2016-6296: Heap buffer overflow vulnerability in
    simplestring_addn in simplestring.c (bsc#991437).

  - CVE-2016-5769: Mcrypt: Heap Overflow due to integer
    overflows (bsc#986388).

  - CVE-2015-8935: XSS in header() with Internet Explorer
    (bsc#986004).

  - CVE-2016-5772: Double free corruption in
    wddx_deserialize (bsc#986244).

  - CVE-2016-5766: Integer Overflow in _gd2GetHeader()
    resulting in heap overflow (bsc#986386).

  - CVE-2016-5767: Integer Overflow in
    gdImagePaletteToTrueColor() resulting in heap overflow
    (bsc#986393).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8935.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5399.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5766.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5769.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5772.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6288.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6289.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6290.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6291.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6296.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6297.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162080-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aca4cf4d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-php5-12696=1

SUSE Linux Enterprise Debuginfo 11-SP2:zypper in -t patch
dbgsp2-php5-12696=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:X");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", reference:"apache2-mod_php5-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-bcmath-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-bz2-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-calendar-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-ctype-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-curl-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-dba-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-dbase-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-dom-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-exif-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-fastcgi-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-ftp-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-gd-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-gettext-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-gmp-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-hash-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-iconv-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-json-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-ldap-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-mbstring-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-mcrypt-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-mysql-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-odbc-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-openssl-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-pcntl-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-pdo-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-pear-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-pgsql-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-pspell-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-shmop-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-snmp-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-soap-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-suhosin-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-sysvmsg-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-sysvsem-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-sysvshm-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-tokenizer-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-wddx-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-xmlreader-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-xmlrpc-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-xmlwriter-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-xsl-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-zip-5.2.14-0.7.30.89.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php5-zlib-5.2.14-0.7.30.89.1")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php5");
}
