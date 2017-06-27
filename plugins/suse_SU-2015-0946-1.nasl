#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0946-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83860);
  script_version("$Revision: 2.17 $");
  script_cvs_date("$Date: 2016/08/18 13:36:11 $");

  script_cve_id("CVE-2014-3569", "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206", "CVE-2015-0405", "CVE-2015-0423", "CVE-2015-0433", "CVE-2015-0438", "CVE-2015-0439", "CVE-2015-0441", "CVE-2015-0498", "CVE-2015-0499", "CVE-2015-0500", "CVE-2015-0501", "CVE-2015-0503", "CVE-2015-0505", "CVE-2015-0506", "CVE-2015-0507", "CVE-2015-0508", "CVE-2015-0511", "CVE-2015-2305", "CVE-2015-2566", "CVE-2015-2567", "CVE-2015-2568", "CVE-2015-2571", "CVE-2015-2573", "CVE-2015-2576");
  script_bugtraq_id(71934, 71935, 71936, 71937, 71939, 71940, 71941, 71942, 72611, 74070, 74073, 74078, 74081, 74085, 74086, 74089, 74091, 74095, 74098, 74102, 74103, 74107, 74110, 74112, 74115, 74120, 74121, 74123, 74126, 74130, 74133, 74137, 75769);
  script_osvdb_id(116423, 116790, 116791, 116792, 116793, 116794, 116795, 116796, 118433, 120722, 120723, 120724, 120725, 120726, 120727, 120728, 120729, 120730, 120731, 120732, 120733, 120734, 120735, 120736, 120737, 120738, 120739, 120740, 120741, 120742, 120743);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : MySQL (SUSE-SU-2015:0946-1) (FREAK)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MySQL was updated to version 5.5.43 to fix several security and non
security issues :

CVEs fixed: CVE-2014-3569, CVE-2014-3570, CVE-2014-3571,
CVE-2014-3572, CVE-2014-8275, CVE-2015-0204, CVE-2015-0205,
CVE-2015-0206, CVE-2015-0405, CVE-2015-0423, CVE-2015-0433,
CVE-2015-0438, CVE-2015-0439, CVE-2015-0441, CVE-2015-0498,
CVE-2015-0499, CVE-2015-0500, CVE-2015-0501, CVE-2015-0503,
CVE-2015-0505, CVE-2015-0506, CVE-2015-0507, CVE-2015-0508,
CVE-2015-0511, CVE-2015-2566, CVE-2015-2567, CVE-2015-2568,
CVE-2015-2571, CVE-2015-2573, CVE-2015-2576.

Fix integer overflow in regcomp (Henry Spencer's regex library) for
excessively long pattern strings. (bnc#922043, CVE-2015-2305)

For a comprehensive list of changes, refer to <a
href='http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-43.html'
>http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-43.html</a>.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-43.html'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-43.html</a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927623"
  );
  # https://download.suse.com/patch/finder/?keywords=bf7ed7fc98aa76bac61b9bec767d2098
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dca0dc5f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3570.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3572.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8275.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0204.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0205.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0206.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0405.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0433.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0438.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0439.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0441.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0498.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0499.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0500.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0501.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0503.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0505.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0506.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0507.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2305.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2566.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2567.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2568.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2573.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2576.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150946-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?46419ceb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11 SP3 :

zypper in -t patch sdksp3-libmysql55client18=10661

SUSE Linux Enterprise Server 11 SP3 for VMware :

zypper in -t patch slessp3-libmysql55client18=10661

SUSE Linux Enterprise Server 11 SP3 :

zypper in -t patch slessp3-libmysql55client18=10661

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-libmysql55client18=10661

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient_r15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/26");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/27");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libmysqlclient15-32bit-5.0.96-0.6.20")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libmysqlclient15-32bit-5.0.96-0.6.20")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysql55client18-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysql55client_r18-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysqlclient15-5.0.96-0.6.20")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysqlclient_r15-5.0.96-0.6.20")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-client-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-tools-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysql55client18-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysql55client_r18-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysqlclient15-5.0.96-0.6.20")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysqlclient_r15-5.0.96-0.6.20")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"mysql-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"mysql-client-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysqlclient15-32bit-5.0.96-0.6.20")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysqlclient_r15-32bit-5.0.96-0.6.20")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libmysql55client18-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libmysql55client_r18-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libmysqlclient15-5.0.96-0.6.20")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libmysqlclient_r15-5.0.96-0.6.20")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"mysql-5.5.43-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"mysql-client-5.5.43-0.7.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MySQL");
}
