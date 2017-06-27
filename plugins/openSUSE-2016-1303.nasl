#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1303.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94906);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/16 14:45:48 $");

  script_cve_id("CVE-2015-3210", "CVE-2015-3217", "CVE-2015-5073", "CVE-2015-8380", "CVE-2016-1283", "CVE-2016-3191");

  script_name(english:"openSUSE Security Update : pcre (openSUSE-2016-1303)");
  script_summary(english:"Check for the openSUSE-2016-1303 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This version fixes a number of vulnerabilities that affect pcre and
applications using the libary when accepting untrusted input as
regular expressions or as part thereof. Remote attackers could have
caused the application to crash, disclose information or potentially
execute arbitrary code.

  - Update to PCRE 8.39 FATE#320298 boo#972127.

  - CVE-2015-3210: heap buffer overflow in pcre_compile2() /
    compile_regex() (boo#933288)

  - CVE-2015-3217: pcre: PCRE Library Call Stack Overflow
    Vulnerability in match() (boo#933878)

  - CVE-2015-5073: pcre: Library Heap Overflow Vulnerability
    in find_fixedlength() (boo#936227)

  - boo#942865: heap overflow in compile_regex()

  - CVE-2015-8380: pcre: heap overflow in pcre_exec
    (boo#957566)

  - boo#957598: various security issues fixed in pcre 8.37
    and 8.38 release

  - CVE-2016-1283: pcre: Heap buffer overflow in
    pcre_compile2 causes DoS (boo#960837)

  - CVE-2016-3191: pcre: workspace overflow for (*ACCEPT)
    with deeply nested parentheses (boo#971741)"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957598"
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
  script_set_attribute(attribute:"solution", value:"Update the affected pcre packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/16");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libpcre1-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcre1-debuginfo-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcre16-0-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcre16-0-debuginfo-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcrecpp0-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcrecpp0-debuginfo-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcreposix0-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcreposix0-debuginfo-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcre-debugsource-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcre-devel-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcre-devel-static-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcre-tools-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcre-tools-debuginfo-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcre1-32bit-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcre1-debuginfo-32bit-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcre16-0-32bit-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcre16-0-debuginfo-32bit-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcrecpp0-32bit-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcrecpp0-debuginfo-32bit-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcreposix0-32bit-8.39-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcreposix0-debuginfo-32bit-8.39-3.8.1") ) flag++;

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
