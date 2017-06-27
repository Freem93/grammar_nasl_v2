#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0743-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83716);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/07/08 14:36:38 $");

  script_cve_id("CVE-2010-5298", "CVE-2012-5615", "CVE-2014-0195", "CVE-2014-0198", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-2494", "CVE-2014-3470", "CVE-2014-4207", "CVE-2014-4258", "CVE-2014-4260", "CVE-2014-4274", "CVE-2014-4287", "CVE-2014-6463", "CVE-2014-6464", "CVE-2014-6469", "CVE-2014-6474", "CVE-2014-6478", "CVE-2014-6484", "CVE-2014-6489", "CVE-2014-6491", "CVE-2014-6494", "CVE-2014-6495", "CVE-2014-6496", "CVE-2014-6500", "CVE-2014-6505", "CVE-2014-6507", "CVE-2014-6520", "CVE-2014-6530", "CVE-2014-6551", "CVE-2014-6555", "CVE-2014-6559", "CVE-2014-6564", "CVE-2014-6568", "CVE-2015-0374", "CVE-2015-0381", "CVE-2015-0382", "CVE-2015-0391", "CVE-2015-0411", "CVE-2015-0432");
  script_bugtraq_id(56766, 66801, 67193, 67898, 67899, 67900, 67901, 68564, 68573, 68579, 68593, 69732, 70444, 70446, 70448, 70451, 70455, 70462, 70469, 70478, 70486, 70487, 70489, 70496, 70497, 70510, 70511, 70516, 70517, 70525, 70530, 70532, 70540, 70550, 72191, 72200, 72205, 72210, 72214, 72217, 72227);
  script_osvdb_id(88067, 105763, 106531, 107729, 107730, 107731, 107732, 109156, 109157, 109158, 109160, 109726, 113252, 113253, 113254, 113255, 113256, 113257, 113258, 113259, 113260, 113261, 113262, 113263, 113264, 113265, 113266, 113267, 113268, 113269, 113270, 113271, 113272, 117329, 117330, 117331, 117333, 117335, 117336, 117337);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : mariadb (SUSE-SU-2015:0743-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"mariadb was updated to version 10.0.16 to fix 40 security issues.

These security issues were fixed :

  - CVE-2015-0411: Unspecified vulnerability in Oracle MySQL
    Server 5.5.40 and earlier, and 5.6.21 and earlier,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via unknown vectors related
    to Server : Security : Encryption (bnc#915911).

  - CVE-2015-0382: Unspecified vulnerability in Oracle MySQL
    Server 5.5.40 and earlier and 5.6.21 and earlier allowed
    remote attackers to affect availability via unknown
    vectors related to Server : Replication, a different
    vulnerability than CVE-2015-0381 (bnc#915911).

  - CVE-2015-0381: Unspecified vulnerability in Oracle MySQL
    Server 5.5.40 and earlier and 5.6.21 and earlier allowed
    remote attackers to affect availability via unknown
    vectors related to Server : Replication, a different
    vulnerability than CVE-2015-0382 (bnc#915911).

  - CVE-2015-0432: Unspecified vulnerability in Oracle MySQL
    Server 5.5.40 and earlier allowed remote authenticated
    users to affect availability via vectors related to
    Server : InnoDB : DDL : Foreign Key (bnc#915911).

  - CVE-2014-6568: Unspecified vulnerability in Oracle MySQL
    Server 5.5.40 and earlier, and 5.6.21 and earlier,
    allowed remote authenticated users to affect
    availability via vectors related to Server : InnoDB :
    DML (bnc#915911).

  - CVE-2015-0374: Unspecified vulnerability in Oracle MySQL
    Server 5.5.40 and earlier and 5.6.21 and earlier allowed
    remote authenticated users to affect confidentiality via
    unknown vectors related to Server : Security :
    Privileges : Foreign Key (bnc#915911).

  - CVE-2014-6507: Unspecified vulnerability in Oracle MySQL
    Server 5.5.39 and earlier, and 5.6.20 and earlier,
    allowed remote authenticated users to affect
    confidentiality, integrity, and availability via vectors
    related to SERVER:DML (bnc#915912).

  - CVE-2014-6491: Unspecified vulnerability in Oracle MySQL
    Server 5.5.39 and earlier and 5.6.20 and earlier allowed
    remote attackers to affect confidentiality, integrity,
    and availability via vectors related to
    SERVER:SSL:yaSSL, a different vulnerability than
    CVE-2014-6500 (bnc#915912).

  - CVE-2014-6500: Unspecified vulnerability in Oracle MySQL
    Server 5.5.39 and earlier, and 5.6.20 and earlier,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via vectors related to
    SERVER:SSL:yaSSL, a different vulnerability than
    CVE-2014-6491 (bnc#915912).

  - CVE-2014-6469: Unspecified vulnerability in Oracle MySQL
    Server 5.5.39 and eariler and 5.6.20 and earlier allowed
    remote authenticated users to affect availability via
    vectors related to SERVER:OPTIMIZER (bnc#915912).

  - CVE-2014-6555: Unspecified vulnerability in Oracle MySQL
    Server 5.5.39 and earlier and 5.6.20 and earlier allowed
    remote authenticated users to affect confidentiality,
    integrity, and availability via vectors related to
    SERVER:DML (bnc#915912).

  - CVE-2014-6559: Unspecified vulnerability in Oracle MySQL
    Server 5.5.39 and earlier, and 5.6.20 and earlier,
    allowed remote attackers to affect confidentiality via
    vectors related to C API SSL CERTIFICATE HANDLING
    (bnc#915912).

  - CVE-2014-6494: Unspecified vulnerability in Oracle MySQL
    Server 5.5.39 and earlier, and 5.6.20 and earlier,
    allowed remote attackers to affect availability via
    vectors related to CLIENT:SSL:yaSSL, a different
    vulnerability than CVE-2014-6496 (bnc#915912).

  - CVE-2014-6496: Unspecified vulnerability in Oracle MySQL
    Server 5.5.39 and earlier, and 5.6.20 and earlier,
    allowed remote attackers to affect availability via
    vectors related to CLIENT:SSL:yaSSL, a different
    vulnerability than CVE-2014-6494 (bnc#915912).

  - CVE-2014-6464: Unspecified vulnerability in Oracle MySQL
    Server 5.5.39 and earlier and 5.6.20 and earlier allowed
    remote authenticated users to affect availability via
    vectors related to SERVER:INNODB DML FOREIGN KEYS
    (bnc#915912).

  - CVE-2010-5298: Race condition in the ssl3_read_bytes
    function in s3_pkt.c in OpenSSL through 1.0.1g, when
    SSL_MODE_RELEASE_BUFFERS is enabled, allowed remote
    attackers to inject data across sessions or cause a
    denial of service (use-after-free and parsing error) via
    an SSL connection in a multithreaded environment
    (bnc#873351).

  - CVE-2014-0195: The dtls1_reassemble_fragment function in
    d1_both.c in OpenSSL before 0.9.8za, 1.0.0 before
    1.0.0m, and 1.0.1 before 1.0.1h did not properly
    validate fragment lengths in DTLS ClientHello messages,
    which allowed remote attackers to execute arbitrary code
    or cause a denial of service (buffer overflow and
    application crash) via a long non-initial fragment
    (bnc#880891).

  - CVE-2014-0198: The do_ssl3_write function in s3_pkt.c in
    OpenSSL 1.x through 1.0.1g, when
    SSL_MODE_RELEASE_BUFFERS is enabled, did not properly
    manage a buffer pointer during certain recursive calls,
    which allowed remote attackers to cause a denial of
    service (NULL pointer dereference and application crash)
    via vectors that trigger an alert condition
    (bnc#876282).

  - CVE-2014-0221: The dtls1_get_message_fragment function
    in d1_both.c in OpenSSL before 0.9.8za, 1.0.0 before
    1.0.0m, and 1.0.1 before 1.0.1h allowed remote attackers
    to cause a denial of service (recursion and client
    crash) via a DTLS hello message in an invalid DTLS
    handshake (bnc#915913).

  - CVE-2014-0224: OpenSSL before 0.9.8za, 1.0.0 before
    1.0.0m, and 1.0.1 before 1.0.1h did not properly
    restrict processing of ChangeCipherSpec messages, which
    allowed man-in-the-middle attackers to trigger use of a
    zero-length master key in certain OpenSSL-to-OpenSSL
    communications, and consequently hijack sessions or
    obtain sensitive information, via a crafted TLS
    handshake, aka the 'CCS Injection' vulnerability
    (bnc#915913).

  - CVE-2014-3470: The ssl3_send_client_key_exchange
    function in s3_clnt.c in OpenSSL before 0.9.8za, 1.0.0
    before 1.0.0m, and 1.0.1 before 1.0.1h, when an
    anonymous ECDH cipher suite is used, allowed remote
    attackers to cause a denial of service (NULL pointer
    dereference and client crash) by triggering a NULL
    certificate value (bnc#915913).

  - CVE-2014-6474: Unspecified vulnerability in Oracle MySQL
    Server 5.6.19 and earlier allowed remote authenticated
    users to affect availability via vectors related to
    SERVER:MEMCACHED (bnc#915913).

  - CVE-2014-6489: Unspecified vulnerability in Oracle MySQL
    Server 5.6.19 and earlier allowed remote authenticated
    users to affect integrity and availability via vectors
    related to SERVER:SP (bnc#915913).

  - CVE-2014-6564: Unspecified vulnerability in Oracle MySQL
    Server 5.6.19 and earlier allowed remote authenticated
    users to affect availability via vectors related to
    SERVER:INNODB FULLTEXT SEARCH DML (bnc#915913).

  - CVE-2012-5615: Oracle MySQL 5.5.38 and earlier, 5.6.19
    and earlier, and MariaDB 5.5.28a, 5.3.11, 5.2.13,
    5.1.66, and possibly other versions, generates different
    error messages with different time delays depending on
    whether a user name exists, which allowed remote
    attackers to enumerate valid usernames (bnc#915913).

  - CVE-2014-4274: Unspecified vulnerability in Oracle MySQL
    Server 5.5.38 and earlier and 5.6.19 and earlier allowed
    local users to affect confidentiality, integrity, and
    availability via vectors related to SERVER:MyISAM
    (bnc#896400).

  - CVE-2014-4287: Unspecified vulnerability in Oracle MySQL
    Server 5.5.38 and earlier and 5.6.19 and earlier allowed
    remote authenticated users to affect availability via
    vectors related to SERVER:CHARACTER SETS (bnc#915913).

  - CVE-2014-6463: Unspecified vulnerability in Oracle MySQL
    Server 5.5.38 and earlier and 5.6.19 and earlier allowed
    remote authenticated users to affect availability via
    vectors related to SERVER:REPLICATION ROW FORMAT BINARY
    LOG DML (bnc#915913).

  - CVE-2014-6478: Unspecified vulnerability in Oracle MySQL
    Server 5.5.38 and earlier, and 5.6.19 and earlier,
    allowed remote attackers to affect integrity via vectors
    related to SERVER:SSL:yaSSL (bnc#915913).

  - CVE-2014-6484: Unspecified vulnerability in Oracle MySQL
    Server 5.5.38 and earlier, and 5.6.19 and earlier,
    allowed remote authenticated users to affect
    availability via vectors related to SERVER:DML
    (bnc#915913).

  - CVE-2014-6495: Unspecified vulnerability in Oracle MySQL
    Server 5.5.38 and earlier, and 5.6.19 and earlier,
    allowed remote attackers to affect availability via
    vectors related to SERVER:SSL:yaSSL (bnc#915913).

  - CVE-2014-6505: Unspecified vulnerability in Oracle MySQL
    Server 5.5.38 and earlier, and 5.6.19 and earlier,
    allowed remote authenticated users to affect
    availability via vectors related to SERVER:MEMORY
    STORAGE ENGINE (bnc#915913).

  - CVE-2014-6520: Unspecified vulnerability in Oracle MySQL
    Server 5.5.38 and earlier allowed remote authenticated
    users to affect availability via vectors related to
    SERVER:DDL (bnc#915913).

  - CVE-2014-6530: Unspecified vulnerability in Oracle MySQL
    Server 5.5.38 and earlier, and 5.6.19 and earlier,
    allowed remote authenticated users to affect
    confidentiality, integrity, and availability via vectors
    related to CLIENT:MYSQLDUMP (bnc#915913).

  - CVE-2014-6551: Unspecified vulnerability in Oracle MySQL
    Server 5.5.38 and earlier and 5.6.19 and earlier allowed
    local users to affect confidentiality via vectors
    related to CLIENT:MYSQLADMIN (bnc#915913).

  - CVE-2015-0391: Unspecified vulnerability in Oracle MySQL
    Server 5.5.38 and earlier, and 5.6.19 and earlier,
    allowed remote authenticated users to affect
    availability via vectors related to DDL (bnc#915913).

  - CVE-2014-4258: Unspecified vulnerability in the MySQL
    Server component in Oracle MySQL 5.5.37 and earlier and
    5.6.17 and earlier allowed remote authenticated users to
    affect confidentiality, integrity, and availability via
    vectors related to SRINFOSC (bnc#915914).

  - CVE-2014-4260: Unspecified vulnerability in the MySQL
    Server component in Oracle MySQL 5.5.37 and earlier, and
    5.6.17 and earlier, allowed remote authenticated users
    to affect integrity and availability via vectors related
    to SRCHAR (bnc#915914).

  - CVE-2014-2494: Unspecified vulnerability in the MySQL
    Server component in Oracle MySQL 5.5.37 and earlier
    allowed remote authenticated users to affect
    availability via vectors related to ENARC (bnc#915914).

  - CVE-2014-4207: Unspecified vulnerability in the MySQL
    Server component in Oracle MySQL 5.5.37 and earlier
    allowed remote authenticated users to affect
    availability via vectors related to SROPTZR
    (bnc#915914).

These non-security issues were fixed :

  - Get query produced incorrect results in MariaDB 10.0.11
    vs MySQL 5.5 - SLES12 (bnc#906194).

  - After update to version 10.0.14 mariadb did not start -
    Job for mysql.service failed (bnc#911442).

  - Fix crash when disk full situation is reached on alter
    table (bnc#904627).

  - Allow md5 in FIPS mode (bnc#911556).

  - Fixed a situation when bit and hex string literals
    unintentionally changed column names (bnc#919229).

Release notes: https://kb.askmonty.org/en/mariadb-10016-release-notes/

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.askmonty.org/en/mariadb-10016-release-notes/"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150743-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fec48b8d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-170=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-170=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-170=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-170=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-debuginfo-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-client-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-client-debuginfo-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-debuginfo-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-debugsource-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-errormessages-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-tools-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-tools-debuginfo-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-32bit-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-debuginfo-32bit-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmysqlclient18-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmysqlclient_r18-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mariadb-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mariadb-client-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mariadb-client-debuginfo-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mariadb-debuginfo-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mariadb-debugsource-10.0.16-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mariadb-errormessages-10.0.16-15.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}
