#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:3161-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(95915);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/27 20:33:26 $");

  script_cve_id("CVE-2014-8964", "CVE-2015-2325", "CVE-2015-2327", "CVE-2015-2328", "CVE-2015-3210", "CVE-2015-3217", "CVE-2015-5073", "CVE-2015-8380", "CVE-2015-8381", "CVE-2015-8382", "CVE-2015-8383", "CVE-2015-8384", "CVE-2015-8385", "CVE-2015-8386", "CVE-2015-8387", "CVE-2015-8388", "CVE-2015-8389", "CVE-2015-8390", "CVE-2015-8391", "CVE-2015-8392", "CVE-2015-8393", "CVE-2015-8394", "CVE-2015-8395", "CVE-2016-1283", "CVE-2016-3191");
  script_bugtraq_id(71206, 74934, 75018, 75175, 75430);
  script_osvdb_id(109038, 109910, 115004, 119871, 122791, 122901, 123810, 125775, 125843, 126620, 130785, 131055, 131057, 131058, 131059, 131060, 131061, 131062, 131063, 131064, 131065, 131066, 131067, 131068, 132469, 134395);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : pcre (SUSE-SU-2016:3161-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pcre to version 8.39 (bsc#972127) fixes several
issues. If you use pcre extensively please be aware that this is an
update to a new version. Please make sure that your software works
with the updated version. This version fixes a number of
vulnerabilities that affect pcre and applications using the libary
when accepting untrusted input as regular expressions or as part
thereof. Remote attackers could have caused the application to crash,
disclose information or potentially execute arbitrary code. These
security issues were fixed :

  - CVE-2014-8964: Heap-based buffer overflow in PCRE
    allowed remote attackers to cause a denial of service
    (crash) or have other unspecified impact via a crafted
    regular expression, related to an assertion that allows
    zero repeats (bsc#906574).

  - CVE-2015-2325: Heap buffer overflow in compile_branch()
    (bsc#924960).

  - CVE-2015-3210: Heap buffer overflow in pcre_compile2() /
    compile_regex() (bsc#933288)

  - CVE-2015-3217: PCRE Library Call Stack Overflow
    Vulnerability in match() (bsc#933878).

  - CVE-2015-5073: Library Heap Overflow Vulnerability in
    find_fixedlength() (bsc#936227).

  - bsc#942865: heap overflow in compile_regex()

  - CVE-2015-8380: The pcre_exec function in pcre_exec.c
    mishandled a // pattern with a \01 string, which allowed
    remote attackers to cause a denial of service
    (heap-based buffer overflow) or possibly have
    unspecified other impact via a crafted regular
    expression, as demonstrated by a JavaScript RegExp
    object encountered by Konqueror (bsc#957566).

  - CVE-2015-2327: PCRE mishandled certain patterns with
    internal recursive back references, which allowed remote
    attackers to cause a denial of service (segmentation
    fault) or possibly have unspecified other impact via a
    crafted regular expression, as demonstrated by a
    JavaScript RegExp object encountered by Konqueror
    (bsc#957567).

  - bsc#957598: Various security issues

  - CVE-2015-8381: Heap Overflow in compile_regex()
    (bsc#957598).

  - CVE-2015-8382: Regular Expression Uninitialized Pointer
    Information Disclosure Vulnerability
    (ZDI-CAN-2547)(bsc#957598).

  - CVE-2015-8383: Buffer overflow caused by repeated
    conditional group(bsc#957598).

  - CVE-2015-8384: Buffer overflow caused by recursive back
    reference by name within certain group(bsc#957598).

  - CVE-2015-8385: Buffer overflow caused by forward
    reference by name to certain group(bsc#957598).

  - CVE-2015-8386: Buffer overflow caused by lookbehind
    assertion(bsc#957598).

  - CVE-2015-8387: Integer overflow in subroutine
    calls(bsc#957598).

  - CVE-2015-8388: Buffer overflow caused by certain
    patterns with an unmatched closing
    parenthesis(bsc#957598).

  - CVE-2015-8389: Infinite recursion in JIT compiler when
    processing certain patterns(bsc#957598).

  - CVE-2015-8390: Reading from uninitialized memory when
    processing certain patterns(bsc#957598).

  - CVE-2015-8391: Some pathological patterns causes
    pcre_compile() to run for a very long time(bsc#957598).

  - CVE-2015-8392: Buffer overflow caused by certain
    patterns with duplicated named groups(bsc#957598).

  - CVE-2015-8393: Information leak when running pcgrep -q
    on crafted binary(bsc#957598).

  - CVE-2015-8394: Integer overflow caused by missing check
    for certain conditions(bsc#957598).

  - CVE-2015-8395: Buffer overflow caused by certain
    references(bsc#957598).

  - CVE-2015-2328: PCRE mishandled the /((?(R)a|(?1)))+/
    pattern and related patterns with certain recursion,
    which allowed remote attackers to cause a denial of
    service (segmentation fault) or possibly have
    unspecified other impact via a crafted regular
    expression (bsc#957600).

  - CVE-2016-1283: The pcre_compile2 function in
    pcre_compile.c in PCRE mishandled certain patterns with
    named subgroups, which allowed remote attackers to cause
    a denial of service (heap-based buffer overflow) or
    possibly have unspecified other impact via a crafted
    regular expression (bsc#960837).

  - CVE-2016-3191: The compile_branch function in
    pcre_compile.c in pcre2_compile.c mishandled patterns
    containing an (*ACCEPT) substring in conjunction with
    nested parentheses, which allowed remote attackers to
    execute arbitrary code or cause a denial of service
    (stack-based buffer overflow) via a crafted regular
    expression (bsc#971741). These non-security issues were
    fixed :

  - JIT compiler improvements

  - performance improvements

  - The Unicode data tables have been updated to Unicode
    7.0.0.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/906574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8964.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2325.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2327.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2328.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3210.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3217.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5073.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8380.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8381.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8382.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8384.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8385.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8386.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8387.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8388.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8389.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8390.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8391.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8392.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8393.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8394.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8395.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1283.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3191.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20163161-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eca1fd8f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2016-1827=1

SUSE Linux Enterprise Workstation Extension 12-SP1:zypper in -t patch
SUSE-SLE-WE-12-SP1-2016-1827=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2016-1827=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1827=1

SUSE Linux Enterprise Server for SAP 12:zypper in -t patch
SUSE-SLE-SAP-12-2016-1827=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2016-1827=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2016-1827=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1827=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2016-1827=1

SUSE Linux Enterprise High Availability 12-SP2:zypper in -t patch
SUSE-SLE-HA-12-SP2-2016-1827=1

SUSE Linux Enterprise High Availability 12-SP1:zypper in -t patch
SUSE-SLE-HA-12-SP1-2016-1827=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2016-1827=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1827=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcre1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcre1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcre16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcre16-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcrecpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcrecpp0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcre-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0|1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpcre1-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpcre1-debuginfo-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpcre16-0-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpcre16-0-debuginfo-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"pcre-debugsource-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpcre1-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpcre1-debuginfo-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpcre1-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpcre1-debuginfo-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpcre16-0-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpcre16-0-debuginfo-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"pcre-debugsource-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpcre1-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpcre1-debuginfo-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libpcre1-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libpcre1-debuginfo-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libpcre16-0-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libpcre16-0-debuginfo-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"pcre-debugsource-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libpcre1-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libpcre1-debuginfo-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpcre1-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpcre1-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpcre1-debuginfo-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpcre1-debuginfo-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpcre16-0-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpcre16-0-debuginfo-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpcrecpp0-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpcrecpp0-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpcrecpp0-debuginfo-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpcrecpp0-debuginfo-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"pcre-debugsource-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libpcre1-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libpcre1-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libpcre1-debuginfo-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libpcre1-debuginfo-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libpcre16-0-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libpcre16-0-debuginfo-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libpcrecpp0-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libpcrecpp0-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libpcrecpp0-debuginfo-32bit-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libpcrecpp0-debuginfo-8.39-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"pcre-debugsource-8.39-7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcre");
}
