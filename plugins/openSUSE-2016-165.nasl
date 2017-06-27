#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-165.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88616);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2015-5969", "CVE-2015-7744", "CVE-2016-0502", "CVE-2016-0503", "CVE-2016-0504", "CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0594", "CVE-2016-0595", "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0600", "CVE-2016-0605", "CVE-2016-0606", "CVE-2016-0607", "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0610", "CVE-2016-0611");

  script_name(english:"openSUSE Security Update : MySQL (openSUSE-2016-165)");
  script_summary(english:"Check for the openSUSE-2016-165 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to MySQL 5.6.28 fixes the following issues (bsc#962779) :

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

  - CVE-2016-0503: Unspecified vulnerability in Oracle MySQL
    5.6.27 and earlier and 5.7.9 allows remote authenticated
    users to affect availability via vectors related to DML,
    a different vulnerability than CVE-2016-0504. 

  - CVE-2016-0504: Unspecified vulnerability in Oracle MySQL
    5.6.27 and earlier and 5.7.9 allows remote authenticated
    users to affect availability via vectors related to DML,
    a different vulnerability than CVE-2016-0503. 

  - CVE-2016-0505: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 allows
    remote authenticated users to affect availability via
    unknown vectors related to Options. 

  - CVE-2016-0546: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 allows
    local users to affect confidentiality, integrity, and
    availability via unknown vectors related to Client. 

  - CVE-2016-0594: Unspecified vulnerability in Oracle MySQL
    5.6.21 and earlier allows remote authenticated users to
    affect availability via vectors related to DML. 

  - CVE-2016-0595: Unspecified vulnerability in Oracle MySQL
    5.6.27 and earlier allows remote authenticated users to
    affect availability via vectors related to DML. 

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

  - CVE-2016-0605: Unspecified vulnerability in Oracle MySQL
    5.6.26 and earlier allows remote authenticated users to
    affect availability via unknown vectors. 

  - CVE-2016-0606: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 allows
    remote authenticated users to affect integrity via
    unknown vectors related to encryption. 

  - CVE-2016-0607: Unspecified vulnerability in Oracle MySQL
    5.6.27 and earlier and 5.7.9 allows remote authenticated
    users to affect availability via unknown vectors related
    to replication. 

  - CVE-2016-0608: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 allows
    remote authenticated users to affect availability via
    vectors related to UDF. 

  - CVE-2016-0609: Unspecified vulnerability in Oracle MySQL
    5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 allows
    remote authenticated users to affect availability via
    unknown vectors related to privileges. 

  - CVE-2016-0610: Unspecified vulnerability in Oracle MySQL
    5.6.27 and earlier allows remote authenticated users to
    affect availability via unknown vectors related to
    InnoDB. 

  - CVE-2016-0611: Unspecified vulnerability in Oracle MySQL
    5.6.27 and earlier and 5.7.9 allows remote authenticated
    users to affect availability via unknown vectors related
    to Optimizer.

  - CVE-2015-5969: Fixed information leak via
    mysql-systemd-helper script. (bsc#957174)

  - bsc#959724: Possible buffer overflow from incorrect use
    of strcpy() and sprintf()"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962779"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MySQL packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client_r18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libmysql56client18-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysql56client18-debuginfo-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysql56client_r18-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-bench-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-bench-debuginfo-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-client-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-client-debuginfo-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-debuginfo-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-debugsource-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-errormessages-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-test-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-test-debuginfo-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-tools-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-tools-debuginfo-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.28-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysql56client18-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysql56client18-debuginfo-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysql56client_r18-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-bench-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-bench-debuginfo-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-client-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-client-debuginfo-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-debuginfo-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-debugsource-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-errormessages-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-test-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-test-debuginfo-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-tools-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-tools-debuginfo-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.28-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.28-13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysql56client18-32bit / libmysql56client18 / etc");
}
