#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2343-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93615);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2016-3477", "CVE-2016-3521", "CVE-2016-3615", "CVE-2016-5440", "CVE-2016-6662");
  script_osvdb_id(141889, 141891, 141898, 141904, 143530, 144086, 144092);

  script_name(english:"SUSE SLES11 Security Update : mysql (SUSE-SU-2016:2343-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This mysql update to verson 5.5.52 fixes the following issues:
Security issues fixed :

  - CVE-2016-3477: Fixed unspecified vulnerability in
    subcomponent parser (bsc#989913).

  - CVE-2016-3521: Fixed unspecified vulnerability in
    subcomponent types (bsc#989919).

  - CVE-2016-3615: Fixed unspecified vulnerability in
    subcomponent dml (bsc#989922).

  - CVE-2016-5440: Fixed unspecified vulnerability in
    subcomponent rbr (bsc#989926).

  - CVE-2016-6662: A malicious user with SQL and filesystem
    access could create a my.cnf in the datadir and , under
    certain circumstances, execute arbitrary code as mysql
    (or even root) user. (bsc#998309) More details can be
    found on:
    http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-
    52.html
    http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-
    51.html
    http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-
    50.html Bugs fixed :

  - bsc#967374: properly restart mysql multi instances
    during upgrade

  - bnc#937258: multi script to restart after crash

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-50.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-51.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-52.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3521.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3615.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5440.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6662.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162343-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a88a411"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5:zypper in -t patch sleclo50sp3-mysql-12752=1

SUSE Manager Proxy 2.1:zypper in -t patch slemap21-mysql-12752=1

SUSE Manager 2.1:zypper in -t patch sleman21-mysql-12752=1

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-mysql-12752=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-mysql-12752=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-mysql-12752=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-mysql-12752=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-mysql-12752=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-mysql-12752=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/21");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client_r18-32bit-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client18-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client_r18-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-client-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-tools-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysql55client18-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysql55client_r18-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-client-5.5.52-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-tools-5.5.52-0.27.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql");
}
