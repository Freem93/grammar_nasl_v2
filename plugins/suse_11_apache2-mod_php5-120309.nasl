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
  script_id(58740);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/13 15:30:41 $");

  script_cve_id("CVE-2011-1072", "CVE-2011-1466", "CVE-2011-2202", "CVE-2011-3182", "CVE-2011-4153", "CVE-2011-4566", "CVE-2011-4885", "CVE-2012-0057", "CVE-2012-0781", "CVE-2012-0788", "CVE-2012-0789", "CVE-2012-0807", "CVE-2012-0830", "CVE-2012-0831");

  script_name(english:"SuSE 11.1 Security Update : PHP5 (SAT Patch Number 5964)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of php5 fixes multiple security flaws :

  - A php5 upload filename injection was fixed.
    (CVE-2011-2202)

  - A integer overflow in the EXIF extension was fixed that
    could be used by attackers to crash the interpreter or
    potentially read memory. (CVE-2011-4566)

  - Multiple NULL pointer dereferences were fixed that could
    lead to crashes. (CVE-2011-3182)

  - An integer overflow in the PHP calendar extension was
    fixed that could have led to crashes. (CVE-2011-1466)

  - A symlink vulnerability in the PEAR installer could be
    exploited by local attackers to inject code.
    (CVE-2011-1072)

  - missing checks of return values could allow remote
    attackers to cause a denial of service (NULL pointer
    dereference). (CVE-2011-4153)

  - denial of service via hash collisions. (CVE-2011-4885)

  - specially crafted XSLT stylesheets could allow remote
    attackers to create arbitrary files with arbitrary
    content. (CVE-2012-0057)

  - remote attackers can cause a denial of service via
    specially crafted input to an application that attempts
    to perform Tidy::diagnose operations. (CVE-2012-0781)

  - applications that use a PDO driver were prone to denial
    of service flaws which could be exploited remotely.
    (CVE-2012-0788)

  - memory leak in the timezone functionality could allow
    remote attackers to cause a denial of service (memory
    consumption). (CVE-2012-0789)

  - a stack-based buffer overflow in the php5 Suhosin
    extension could allow remote attackers to execute
    arbitrary code via a long string that is used in a
    Set-Cookie HTTP header. (CVE-2012-0807)

  - this fixes an incorrect fix for CVE-2011-4885 which
    could allow remote attackers to execute arbitrary code
    via a request containing a large number of variables.
    (CVE-2012-0830)

  - temporary changes to the magic_quotes_gpc directive
    during the importing of environment variables is not
    properly performed which makes it easier for remote
    attackers to conduct SQL injections. (CVE-2012-0831)

Also the following bugs have been fixed :

  - allow uploading files bigger than 2GB for 64bit systems
    [bnc#709549]

  - amend README.SUSE to discourage using apache module with
    apache2-worker [bnc#728671]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=699711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=709549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=713652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=728671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=733590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=735613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=736169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=741520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=741859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=743308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1072.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1466.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2202.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4153.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4566.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4885.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0057.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0781.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0788.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0789.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0807.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0831.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5964.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:1, reference:"apache2-mod_php5-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-bcmath-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-bz2-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-calendar-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-ctype-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-curl-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-dba-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-dbase-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-dom-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-exif-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-fastcgi-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-ftp-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-gd-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-gettext-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-gmp-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-hash-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-iconv-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-json-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-ldap-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-mbstring-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-mcrypt-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-mysql-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-odbc-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-openssl-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-pcntl-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-pdo-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-pear-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-pgsql-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-pspell-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-shmop-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-snmp-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-soap-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-suhosin-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-sysvmsg-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-sysvsem-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-sysvshm-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-tokenizer-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-wddx-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-xmlreader-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-xmlrpc-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-xmlwriter-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-xsl-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-zip-5.2.14-0.7.30.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"php5-zlib-5.2.14-0.7.30.34.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
