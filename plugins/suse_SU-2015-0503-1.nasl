#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0503-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83699);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2014-3566", "CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395", "CVE-2015-0400", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0410", "CVE-2015-0412");
  script_bugtraq_id(70574, 72132, 72136, 72140, 72142, 72155, 72159, 72162, 72165, 72168, 72169, 72173, 72175);
  script_osvdb_id(113251, 117224, 117225, 117227, 117228, 117232, 117233, 117235, 117236, 117237, 117238, 117239, 117241);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : java-1_7_0-openjdk (SUSE-SU-2015:0503-1) (POODLE)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes 13 security issues.

These security issues were fixed :

  - CVE-2015-0395: Unspecified vulnerability in Oracle Java
    SE 5.0u75, 6u85, 7u72, and 8u25 allowed remote attackers
    to affect confidentiality, integrity, and availability
    via unknown vectors related to Hotspot (bnc#914041).

  - CVE-2015-0400: Unspecified vulnerability in Oracle Java
    SE 6u85, 7u72, and 8u25 allowed remote attackers to
    affect confidentiality via unknown vectors related to
    Libraries (bnc#914041).

  - CVE-2015-0383: Unspecified vulnerability in Oracle Java
    SE 5.0u75, 6u85, 7u72, and 8u25; Java SE Embedded 7u71
    and 8u6; and JRockit R27.8.4 and R28.3.4 allowed local
    users to affect integrity and availability via unknown
    vectors related to Hotspot (bnc#914041).

  - CVE-2015-0412: Unspecified vulnerability in Oracle Java
    SE 6u85, 7u72, and 8u25 allowed remote attackers to
    affect confidentiality, integrity, and availability via
    vectors related to JAX-WS (bnc#914041).

  - CVE-2015-0407: Unspecified vulnerability in Oracle Java
    SE 5.0u75, 6u85, 7u72, and 8u25 allowed remote attackers
    to affect confidentiality via unknown vectors related to
    Swing (bnc#914041).

  - CVE-2015-0408: Unspecified vulnerability in Oracle Java
    SE 5.0u75, 6u85, 7u72, and 8u25 allowed remote attackers
    to affect confidentiality, integrity, and availability
    via vectors related to RMI (bnc#914041).

  - CVE-2014-6585: Unspecified vulnerability in Oracle Java
    SE 5.0u75, 6u85, 7u72, and 8u25 allowed remote attackers
    to affect confidentiality via unknown vectors reelated
    to 2D, a different vulnerability than CVE-2014-6591
    (bnc#914041).

  - CVE-2014-6587: Unspecified vulnerability in Oracle Java
    SE 6u85, 7u72, and 8u25 allowed local users to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Libraries (bnc#914041).

  - CVE-2014-6591: Unspecified vulnerability in the Java SE
    component in Oracle Java SE 5.0u75, 6u85, 7u72, and 8u25
    allowed remote attackers to affect confidentiality via
    unknown vectors related to 2D, a different vulnerability
    than CVE-2014-6585 (bnc#914041).

  - CVE-2014-6593: Unspecified vulnerability in Oracle Java
    SE 5.0u75, 6u85, 7u72, and 8u25; Java SE Embedded 7u71
    and 8u6; and JRockit 27.8.4 and 28.3.4 allowed remote
    attackers to affect confidentiality and integrity via
    vectors related to JSSE (bnc#914041).

  - CVE-2014-6601: Unspecified vulnerability in Oracle Java
    SE 6u85, 7u72, and 8u25 allowed remote attackers to
    affect confidentiality, integrity, and availability via
    unknown vectors related to Hotspot (bnc#914041).

  - CVE-2015-0410: Unspecified vulnerability in the Java SE,
    Java SE Embedded, JRockit component in Oracle Java SE
    5.0u75, 6u85, 7u72, and 8u25; Java SE Embedded 7u71 and
    8u6; and JRockit R27.8.4 and R28.3.4 allowed remote
    attackers to affect availability via unknown vectors
    related to Security (bnc#914041).

  - CVE-2014-3566: The SSL protocol 3.0, as used in OpenSSL
    through 1.0.1i and other products, used nondeterministic
    CBC padding, which made it easier for man-in-the-middle
    attackers to obtain cleartext data via a padding-oracle
    attack, aka the 'POODLE' issue (bnc#901223).

These non-security issues were fixed :

  - Update protocol support (S8046656).

  - Fewer escapes from escape analysis (S8047130).

  - Better GC validation (S8049253).

  - TLAB stability (S8055479).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3566.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6587.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6591.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6593.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6601.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0395.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0400.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0407.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0408.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0410.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/901223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914041"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150503-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?376da17d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-122=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-122=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/09");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-1.7.0.75-11.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.75-11.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-debugsource-1.7.0.75-11.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-demo-1.7.0.75-11.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.75-11.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-devel-1.7.0.75-11.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.75-11.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-headless-1.7.0.75-11.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.75-11.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.75-11.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.75-11.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-debugsource-1.7.0.75-11.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-1.7.0.75-11.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.75-11.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk");
}
