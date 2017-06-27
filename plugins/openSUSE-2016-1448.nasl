#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1448.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95754);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/13 18:01:19 $");

  script_cve_id("CVE-2014-8964", "CVE-2015-2325", "CVE-2015-2327", "CVE-2015-2328", "CVE-2015-3210", "CVE-2015-3217", "CVE-2015-5073", "CVE-2015-8380", "CVE-2015-8381", "CVE-2015-8382", "CVE-2015-8383", "CVE-2015-8384", "CVE-2015-8385", "CVE-2015-8386", "CVE-2015-8387", "CVE-2015-8388", "CVE-2015-8389", "CVE-2015-8390", "CVE-2015-8391", "CVE-2015-8392", "CVE-2015-8393", "CVE-2015-8394", "CVE-2015-8395", "CVE-2016-1283", "CVE-2016-3191");

  script_name(english:"openSUSE Security Update : pcre (openSUSE-2016-1448)");
  script_summary(english:"Check for the openSUSE-2016-1448 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pcre to version 8.39 (bsc#972127) fixes several
issues.

If you use pcre extensively please be aware that this is an update to
a new version. Please make sure that your software works with the
updated version.

This version fixes a number of vulnerabilities that affect pcre and
applications using the libary when accepting untrusted input as
regular expressions or as part thereof. Remote attackers could have
caused the application to crash, disclose information or potentially
execute arbitrary code. These security issues were fixed :

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
    expression (bsc#971741).

These non-security issues were fixed :

  - JIT compiler improvements

  - performance improvements

  - The Unicode data tables have been updated to Unicode
    7.0.0.

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=924960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=933288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=933878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=942865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/320298"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pcre packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre16-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre16-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre16-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre16-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcrecpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcrecpp0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcrecpp0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcrecpp0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcreposix0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcreposix0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcreposix0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcreposix0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcre-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcre-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcre-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcre-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcre-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/13");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libpcre1-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcre1-debuginfo-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcre16-0-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcre16-0-debuginfo-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcrecpp0-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcrecpp0-debuginfo-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcreposix0-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcreposix0-debuginfo-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcre-debugsource-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcre-devel-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcre-devel-static-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcre-tools-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcre-tools-debuginfo-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcre1-32bit-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcre1-debuginfo-32bit-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcre16-0-32bit-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcre16-0-debuginfo-32bit-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcrecpp0-32bit-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcrecpp0-debuginfo-32bit-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcreposix0-32bit-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcreposix0-debuginfo-32bit-8.39-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcre1-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcre1-debuginfo-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcre16-0-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcre16-0-debuginfo-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcrecpp0-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcrecpp0-debuginfo-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcreposix0-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcreposix0-debuginfo-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pcre-debugsource-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pcre-devel-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pcre-devel-static-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pcre-tools-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pcre-tools-debuginfo-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcre1-32bit-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcre1-debuginfo-32bit-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcre16-0-32bit-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcre16-0-debuginfo-32bit-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcrecpp0-32bit-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcrecpp0-debuginfo-32bit-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcreposix0-32bit-8.39-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcreposix0-debuginfo-32bit-8.39-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpcre1-32bit / libpcre1 / libpcre1-debuginfo-32bit / etc");
}
