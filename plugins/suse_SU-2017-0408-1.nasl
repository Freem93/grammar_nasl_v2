#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0408-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(97046);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/07 14:52:10 $");

  script_cve_id("CVE-2016-6664", "CVE-2017-3238", "CVE-2017-3243", "CVE-2017-3244", "CVE-2017-3258", "CVE-2017-3265", "CVE-2017-3291", "CVE-2017-3312", "CVE-2017-3313", "CVE-2017-3317", "CVE-2017-3318");
  script_osvdb_id(145975, 146606, 146607, 150449, 150450, 150452, 150454, 150456, 150457, 150460, 150461, 150463, 150464);

  script_name(english:"SUSE SLES11 Security Update : mysql (SUSE-SU-2017:0408-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This mysql version update to 5.5.54 fixes the following issues :

  - CVE-2017-3318: Unspecified vulnerability affecting Error
    Handling (bsc#1020896)

  - CVE-2017-3317: Unspecified vulnerability affecting
    Logging (bsc#1020894)

  - CVE-2017-3313: Unspecified vulnerability affecting the
    MyISAM component (bsc#1020890)

  - CVE-2017-3312: Insecure error log file handling in
    mysqld_safe, incomplete CVE-2016-6664 (bsc#1020873)

  - CVE-2017-3291: Unrestricted mysqld_safe's ledir
    (bsc#1020884)

  - CVE-2017-3265: Unsafe chmod/chown use in init script
    (bsc#1020885)

  - CVE-2017-3258: Unspecified vulnerability in the DDL
    component (bsc#1020875)

  - CVE-2017-3244: Unspecified vulnerability affecing the
    DML component (bsc#1020877)

  - CVE-2017-3243: Unspecified vulnerability affecting the
    Charsets component (bsc#1020891)

  - CVE-2017-3238: Unspecified vulnerability affecting the
    Optimizer component (bsc#1020882)

  - Applications using the client library for MySQL
    (libmysqlclient.so) had a use-after-free issue that
    could cause the applications to crash (bsc#1022428)
    Release Notes:
    http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-
    54.html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-54.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3238.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3243.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3244.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3258.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3265.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3291.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3312.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3313.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3317.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3318.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170408-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f81b5d21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5:zypper in -t patch sleclo50sp3-mysql-12971=1

SUSE Manager Proxy 2.1:zypper in -t patch slemap21-mysql-12971=1

SUSE Manager 2.1:zypper in -t patch sleman21-mysql-12971=1

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-mysql-12971=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-mysql-12971=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-mysql-12971=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-mysql-12971=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-mysql-12971=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-mysql-12971=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client_r18-32bit-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client18-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client_r18-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-client-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-tools-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysql55client18-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysql55client_r18-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-client-5.5.54-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-tools-5.5.54-0.35.1")) flag++;


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
