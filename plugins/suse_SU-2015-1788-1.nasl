#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1788-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86537);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2015-2582", "CVE-2015-2611", "CVE-2015-2617", "CVE-2015-2620", "CVE-2015-2639", "CVE-2015-2641", "CVE-2015-2643", "CVE-2015-2648", "CVE-2015-2661", "CVE-2015-3152", "CVE-2015-4737", "CVE-2015-4752", "CVE-2015-4756", "CVE-2015-4757", "CVE-2015-4761", "CVE-2015-4767", "CVE-2015-4769", "CVE-2015-4771", "CVE-2015-4772");
  script_bugtraq_id(74398, 75751, 75753, 75759, 75760, 75762, 75770, 75774, 75781, 75785, 75802, 75813, 75815, 75822, 75830, 75835, 75837, 75844, 75849);
  script_osvdb_id(121459, 121460, 121461, 124735, 124736, 124737, 124738, 124739, 124740, 124741, 124742, 124743, 124744, 124745, 124746, 124747, 124748, 124749, 124750, 124751, 124752);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : mysql (SUSE-SU-2015:1788-1) (BACKRONYM)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MySQL was updated to version 5.5.45, fixing bugs and security issues.

A list of all changes can be found on :

- http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-45.html

- http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-44.html

To fix the 'BACKRONYM' security issue (CVE-2015-3152) the behaviour of
the SSL options was changed slightly to meet expectations: Now using
'--ssl-verify-server-cert' and '--ssl[-*]' implies that the ssl
connection is required. The mysql client will now print an error if
ssl is required, but the server can not handle a ssl connection
[bnc#924663], [bnc#928962], [CVE-2015-3152]

Additional bugs fixed :

  - fix rc.mysql-multi script to start instances after
    restart properly [bnc#934401].

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-44.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-45.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2582.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2611.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2617.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2620.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2639.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2641.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2643.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2648.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2661.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3152.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4737.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4752.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4756.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4757.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4761.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4769.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4771.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4772.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151788-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ea75850"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-mysql-12147=1

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-mysql-12147=1

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-mysql-12147=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-mysql-12147=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-mysql-12147=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-mysql-12147=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-mysql-12147=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-mysql-12147=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-mysql-12147=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client_r18-32bit-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client18-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client_r18-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-client-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-tools-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysql55client18-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysql55client_r18-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-client-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-tools-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libmysql55client18-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libmysql55client_r18-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mysql-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mysql-client-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libmysql55client18-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libmysql55client_r18-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mysql-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mysql-client-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysql55client18-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysql55client_r18-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"mysql-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"mysql-client-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libmysql55client18-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libmysql55client_r18-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"mysql-5.5.45-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"mysql-client-5.5.45-0.11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql");
}
