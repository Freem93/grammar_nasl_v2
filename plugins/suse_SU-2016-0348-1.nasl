#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0348-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(88623);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2015-7744", "CVE-2016-0502", "CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0600", "CVE-2016-0606", "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0616");
  script_osvdb_id(133169, 133171, 133175, 133176, 133177, 133179, 133180, 133181, 133185, 133186, 133188, 133190, 133679);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : mysql (SUSE-SU-2016:0348-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to MySQL 5.5.47 fixes the following issues (bsc#962779) :

  - CVE-2015-7744: Lack of verification against faults
    associated with the Chinese Remainder Theorem (CRT)
    process when allowing ephemeral key exchange without low
    memory optimizations on a server, which makes it easier
    for remote attackers to obtain private RSA keys by
    capturing TLS handshakes, aka a Lenstra attack.

  - CVE-2016-0502: Unspecified vulnerability in Oracle MySQL
    5.5.31 and earlier and 5.6.11 and earlier allows remote
    authenticated users to affect availability via unknown
    vectors related to Optimizer.

  - CVE-2016-0505: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 allows
    remote authenticated users to affect availability via
    unknown vectors related to Options.

  - CVE-2016-0546: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 allows
    local users to affect confidentiality, integrity, and
    availability via unknown vectors related to Client.

  - CVE-2016-0596: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier and 5.6.27 and earlier allows remote
    authenticated users to affect availability via vectors
    related to DML.

  - CVE-2016-0597: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 allows
    remote authenticated users to affect availability via
    unknown vectors related to Optimizer.

  - CVE-2016-0598: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 allows
    remote authenticated users to affect availability via
    vectors related to DML.

  - CVE-2016-0600: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 allows
    remote authenticated users to affect availability via
    unknown vectors related to InnoDB.

  - CVE-2016-0606: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 allows
    remote authenticated users to affect integrity via
    unknown vectors related to encryption.

  - CVE-2016-0608: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 allows
    remote authenticated users to affect availability via
    vectors related to UDF.

  - CVE-2016-0609: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 allows
    remote authenticated users to affect availability via
    unknown vectors related to privileges.

  - CVE-2016-0616: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier allows remote authenticated users to
    affect availability via unknown vectors related to
    Optimizer.

  - bsc#959724: Possible buffer overflow from incorrect use
    of strcpy() and sprintf()

The following bugs were fixed :

  - bsc#960961: Incorrect use of plugin-load option in
    default_plugins.cnf

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7744.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0502.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0505.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0546.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0596.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0597.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0598.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0600.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0606.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0608.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0609.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0616.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160348-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e66ebb13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-mysql-12386=1

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-mysql-12386=1

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-mysql-12386=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-mysql-12386=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-mysql-12386=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-mysql-12386=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-mysql-12386=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-mysql-12386=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-mysql-12386=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/08");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client_r18-32bit-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client18-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client_r18-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-client-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-tools-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysql55client18-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysql55client_r18-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-client-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-tools-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libmysql55client18-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libmysql55client_r18-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mysql-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mysql-client-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libmysql55client18-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libmysql55client_r18-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mysql-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mysql-client-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysql55client18-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysql55client_r18-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"mysql-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"mysql-client-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libmysql55client18-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libmysql55client_r18-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"mysql-5.5.47-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"mysql-client-5.5.47-0.17.1")) flag++;


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
