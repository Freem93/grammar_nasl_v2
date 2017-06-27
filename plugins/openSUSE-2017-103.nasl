#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-103.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96546);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/17 14:52:19 $");

  script_cve_id("CVE-2017-5208", "CVE-2017-5331", "CVE-2017-5332", "CVE-2017-5333");

  script_name(english:"openSUSE Security Update : icoutils (openSUSE-2017-103)");
  script_summary(english:"Check for the openSUSE-2017-103 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for icoutils to version 0.31.1 fixes the following 
issues :

  - CVE-2017-5208: An integer overflow allows maliciously
    crafted files to cause DoS or code execution
    (boo#1018756).

  - CVE-2017-5331: Incorrect out of bounds checks in
    check_offset allow for DoS or code execution
    (boo#1018756).

  - CVE-2017-5332: Missing out of bounds checks in
    extract_group_icon_cursor_resource allow for DoS or code
    execution (boo#1018756).

  - CVE-2017-5333: Incorrect out of bounds checks in
    check_offset allow for DoS or code execution
    (boo#1018756)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018756"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icoutils packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icoutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icoutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icoutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"icoutils-0.31.1-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"icoutils-debuginfo-0.31.1-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"icoutils-debugsource-0.31.1-4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icoutils / icoutils-debuginfo / icoutils-debugsource");
}
