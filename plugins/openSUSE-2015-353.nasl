#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-353.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83392);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/13 14:37:10 $");

  script_cve_id("CVE-2014-8964", "CVE-2015-2325", "CVE-2015-2326");

  script_name(english:"openSUSE Security Update : pcre (openSUSE-2015-353)");
  script_summary(english:"Check for the openSUSE-2015-353 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The regular expression library pcre was updated to 8.37 to fix three
security issues and a number of bugs and correctness issues.

The following vulnerabilities were fixed :

  - CVE-2015-2325: Specially crafted regular expressions
    could have caused a heap buffer overlow in
    compile_branch(), potentially allowing the execution of
    arbitrary code. (boo#924960)

  - CVE-2015-2326: Specially crafted regular expressions
    could have caused a heap buffer overlow in
    pcre_compile2(), potentially allowing the execution of
    arbitrary code. [boo#924961]

  - CVE-2014-8964: Specially crafted regular expression
    could have caused a denial of service (crash) or have
    other unspecified impact. [boo#906574]"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=924961"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pcre packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libpcre1-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpcre1-debuginfo-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpcre16-0-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpcre16-0-debuginfo-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpcrecpp0-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpcrecpp0-debuginfo-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpcreposix0-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpcreposix0-debuginfo-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcre-debugsource-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcre-devel-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcre-devel-static-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcre-tools-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcre-tools-debuginfo-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpcre1-32bit-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpcre1-debuginfo-32bit-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpcre16-0-32bit-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpcre16-0-debuginfo-32bit-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpcrecpp0-32bit-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpcrecpp0-debuginfo-32bit-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpcreposix0-32bit-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpcreposix0-debuginfo-32bit-8.37-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcre1-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcre1-debuginfo-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcre16-0-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcre16-0-debuginfo-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcrecpp0-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcrecpp0-debuginfo-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcreposix0-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcreposix0-debuginfo-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcre-debugsource-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcre-devel-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcre-devel-static-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcre-tools-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcre-tools-debuginfo-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcre1-32bit-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcre1-debuginfo-32bit-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcre16-0-32bit-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcre16-0-debuginfo-32bit-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcrecpp0-32bit-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcrecpp0-debuginfo-32bit-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcreposix0-32bit-8.37-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcreposix0-debuginfo-32bit-8.37-3.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpcre1-32bit / libpcre1 / libpcre1-debuginfo-32bit / etc");
}
