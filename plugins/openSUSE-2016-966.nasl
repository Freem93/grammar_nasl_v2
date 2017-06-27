#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-966.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92974);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:13 $");

  script_cve_id("CVE-2016-3191");

  script_name(english:"openSUSE Security Update : pcre2 (openSUSE-2016-966)");
  script_summary(english:"Check for the openSUSE-2016-966 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pcre2 fixes the following issues :

  - pcre2 10.22 :

  - The POSIX wrapper function regcomp() did not used to
    support back references and subroutine calls if called
    with the REG_NOSUB option. It now does.

  - A new function, pcre2_code_copy(), is added, to make a
    copy of a compiled pattern.

  - Support for string callouts is added to pcre2grep.

  - Added the PCRE2_NO_JIT option to pcre2_match().

  - The pcre2_get_error_message() function now returns with
    a negative error code if the error number it is given is
    unknown.

  - Several updates have been made to pcre2test and test
    scripts

  - Fix CVE-2016-3191: workspace overflow for (*ACCEPT) with
    deeply nested parentheses (boo#971741)

  - Update to new upstream release 10.21

  - Improve JIT matching speed of patterns starting with +
    or *.

  - Use memchr() to find the first character in an
    unanchored match in 8-bit mode in the interpreter. This
    gives a significant speed improvement.

  - 10.20 broke the handling of [[:>:]] and [[:<:]] in that
    processing them could involve a buffer overflow if the
    following character was an opening parenthesis.

  - 10.20 also introduced a bug in processing this pattern:
    /((?x)(*:0))#(?'/, which was fixed.

  - A callout with a string argument containing an opening
    square bracket, for example /(?C$[$)(?<]/, was
    incorrectly processed and could provoke a buffer
    overflow.

  - A possessively repeated conditional group that could
    match an empty string, for example, /(?(R))*+/, was
    incorrectly compiled.

  - The Unicode tables have been updated to Unicode 8.0.0.

  - An empty comment (?#) in a pattern was incorrectly
    processed and could provoke a buffer overflow.

  - Fix infinite recursion in the JIT compiler when certain
    patterns /such as (?:|a|){100}x/ are analysed.

  - Some patterns with character classes involving [: and \\
    were incorrectly compiled and could cause reading from
    uninitialized memory or an incorrect error diagnosis.
    Examples are: /[[:\\](?<[::]/ and /[[:\\](?'abc')[a:].

  - A missing closing parenthesis for a callout with a
    string argument was not being diagnosed, possibly
    leading to a buffer overflow.

  - If (?R was followed by - or + incorrect behaviour
    happened instead of a diagnostic.

  - Fixed an issue when \p{Any} inside an xclass did not
    read the current character.

  - About 80 more fixes, which you can read about in the
    ChangeLog shipped with the libpcre2-8-0 package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971741"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pcre2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-16-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-16-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-16-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-16-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-32-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-32-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-32-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-32-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-8-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-8-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-8-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-8-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-posix1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-posix1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-posix1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcre2-posix1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcre2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcre2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcre2-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcre2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcre2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/16");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libpcre2-16-0-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcre2-16-0-debuginfo-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcre2-32-0-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcre2-32-0-debuginfo-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcre2-8-0-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcre2-8-0-debuginfo-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcre2-posix1-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcre2-posix1-debuginfo-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcre2-debugsource-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcre2-devel-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcre2-devel-static-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcre2-tools-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcre2-tools-debuginfo-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcre2-16-0-32bit-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcre2-16-0-debuginfo-32bit-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcre2-32-0-32bit-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcre2-32-0-debuginfo-32bit-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcre2-8-0-32bit-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcre2-8-0-debuginfo-32bit-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcre2-posix1-32bit-10.22-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcre2-posix1-debuginfo-32bit-10.22-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpcre2-16-0 / libpcre2-16-0-32bit / libpcre2-16-0-debuginfo / etc");
}
