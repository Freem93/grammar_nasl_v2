#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1375-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(85379);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2015-0192", "CVE-2015-1931", "CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2619", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2632", "CVE-2015-2637", "CVE-2015-2638", "CVE-2015-2664", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4729", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");
  script_bugtraq_id(73684, 74545, 74733, 75784, 75812, 75818, 75823, 75832, 75833, 75854, 75857, 75861, 75867, 75871, 75874, 75881, 75883, 75890, 75892, 75895, 75985);
  script_osvdb_id(117855, 121762, 122331, 124489, 124617, 124619, 124620, 124621, 124622, 124623, 124625, 124627, 124628, 124629, 124630, 124631, 124633, 124634, 124636, 124637, 124639, 124946);

  script_name(english:"SUSE SLES11 Security Update : java-1_7_0-ibm (SUSE-SU-2015:1375-1) (Bar Mitzvah) (Logjam)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_7_0-ibm was updated to fix 21 security issues.

These security issues were fixed :

  - CVE-2015-4729: Unspecified vulnerability in Oracle Java
    SE 7u80 and 8u45 allowed remote attackers to affect
    confidentiality and integrity via unknown vectors
    related to Deployment (bsc#938895).

  - CVE-2015-4748: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45; JRockit R28.3.6; and Java SE
    Embedded 7u75 and Embedded 8u33 allowed remote attackers
    to affect confidentiality, integrity, and availability
    via unknown vectors related to Security (bsc#938895).

  - CVE-2015-2664: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45 allowed local users to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Deployment (bsc#938895).

  - CVE-2015-0192: Unspecified vulnerability in IBM Java 8
    before SR1, 7 R1 before SR2 FP11, 7 before SR9, 6 R1
    before SR8 FP4, 6 before SR16 FP4, and 5.0 before SR16
    FP10 allowed remote attackers to gain privileges via
    unknown vectors related to the Java Virtual Machine
    (bsc#938895).

  - CVE-2015-2613: Unspecified vulnerability in Oracle Java
    SE 7u80 and 8u45, and Java SE Embedded 7u75 and 8u33
    allowed remote attackers to affect confidentiality via
    vectors related to JCE (bsc#938895).

  - CVE-2015-4731: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45; Java SE Embedded 7u75; and Java
    SE Embedded 8u33 allowed remote attackers to affect
    confidentiality, integrity, and availability via vectors
    related to JMX (bsc#938895).

  - CVE-2015-2637: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45; JavaFX 2.2.80; and Java SE
    Embedded 7u75 and 8u33 allowed remote attackers to
    affect confidentiality via unknown vectors related to 2D
    (bsc#938895).

  - CVE-2015-4733: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45, and Java SE Embedded 7u75 and
    8u33 allowed remote attackers to affect confidentiality,
    integrity, and availability via vectors related to RMI
    (bsc#938895).

  - CVE-2015-4732: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45, and Java SE Embedded 7u75 and
    8u33 allowed remote attackers to affect confidentiality,
    integrity, and availability via unknown vectors related
    to Libraries, a different vulnerability than
    CVE-2015-2590 (bsc#938895).

  - CVE-2015-2621: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45, and Java SE Embedded 7u75 and
    8u33, allowed remote attackers to affect confidentiality
    via vectors related to JMX (bsc#938895).

  - CVE-2015-2619: Unspecified vulnerability in Oracle Java
    SE 7u80 and 8u45, JavaFX 2.2.80, and Java SE Embedded
    7u75 and 8u33 allowed remote attackers to affect
    confidentiality via unknown vectors related to 2D
    (bsc#938895).

  - CVE-2015-2590: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45, and Java SE Embedded 7u75 and
    8u33 allowed remote attackers to affect confidentiality,
    integrity, and availability via unknown vectors related
    to Libraries, a different vulnerability than
    CVE-2015-4732 (bsc#938895).

  - CVE-2015-2638: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45; JavaFX 2.2.80; and Java SE
    Embedded 7u75 and 8u33 allowed remote attackers to
    affect confidentiality, integrity, and availability via
    unknown vectors related to 2D (bsc#938895).

  - CVE-2015-2625: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45; JRockit R28.3.6; and Java SE
    Embedded 7u75 and 8u33 allowed remote attackers to
    affect confidentiality via vectors related to JSSE
    (bsc#938895).

  - CVE-2015-2632: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45 allowed remote attackers to
    affect confidentiality via unknown vectors related to 2D
    (bsc#938895).

  - CVE-2015-1931: Unspecified vulnerability (bsc#938895).

  - CVE-2015-4760: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45 allowed remote attackers to
    affect confidentiality, integrity, and availability via
    unknown vectors related to 2D (bsc#938895).

  - CVE-2015-4000: The TLS protocol 1.2 and earlier, when a
    DHE_EXPORT ciphersuite is enabled on a server but not on
    a client, did not properly convey a DHE_EXPORT choice,
    which allowed man-in-the-middle attackers to conduct
    cipher-downgrade attacks by rewriting a ClientHello with
    DHE replaced by DHE_EXPORT and then rewriting a
    ServerHello with DHE_EXPORT replaced by DHE, aka the
    'Logjam' issue (bsc#935540).

  - CVE-2015-2601: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45, JRockit R28.3.6, and Java SE
    Embedded 7u75 and 8u33 allowed remote attackers to
    affect confidentiality via vectors related to JCE
    (bsc#938895).

  - CVE-2015-2808: The RC4 algorithm, as used in the TLS
    protocol and SSL protocol, did not properly combine
    state data with key data during the initialization
    phase, which made it easier for remote attackers to
    conduct plaintext-recovery attacks against the initial
    bytes of a stream by sniffing network traffic that
    occasionally relies on keys affected by the Invariance
    Weakness, and then using a brute-force approach
    involving LSB values, aka the 'Bar Mitzvah' issue
    (bsc#938895).

  - CVE-2015-4749: Unspecified vulnerability in Oracle Java
    SE 6u95, 7u80, and 8u45; JRockit R28.3.6; and Java SE
    Embedded 7u75 and 8u33 allowed remote attackers to
    affect availability via vectors related to JNDI
    (bsc#938895).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0192.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1931.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2590.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2601.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2613.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2619.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2621.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2625.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2632.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2637.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2638.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2664.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2808.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4729.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4731.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4732.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4733.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4748.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4749.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4760.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151375-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ebe10888"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-java-1_7_0-ibm-12026=1

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-java-1_7_0-ibm-12026=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-java-1_7_0-ibm-12026=1

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-java-1_7_0-ibm-12026=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/31");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-ibm-alsa-1.7.0_sr9.10-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-ibm-plugin-1.7.0_sr9.10-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"java-1_7_0-ibm-1.7.0_sr9.10-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"java-1_7_0-ibm-jdbc-1.7.0_sr9.10-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"java-1_7_0-ibm-alsa-1.7.0_sr9.10-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"java-1_7_0-ibm-plugin-1.7.0_sr9.10-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"java-1_7_0-ibm-alsa-1.7.0_sr9.10-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"java-1_7_0-ibm-plugin-1.7.0_sr9.10-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_7_0-ibm-1.7.0_sr9.10-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_7_0-ibm-devel-1.7.0_sr9.10-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_7_0-ibm-jdbc-1.7.0_sr9.10-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"java-1_7_0-ibm-alsa-1.7.0_sr9.10-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"java-1_7_0-ibm-plugin-1.7.0_sr9.10-9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-ibm");
}
