#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-122.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81254);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/11 13:51:32 $");

  script_cve_id("CVE-2014-2893");

  script_name(english:"openSUSE Security Update : llvm (openSUSE-2015-122)");
  script_summary(english:"Check for the openSUSE-2015-122 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"llvm was updated to fix one security issue.

This security issue was fixed :

  - Insecure temporary file handling in clang's scan-build
    utility (CVE-2014-2893)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=874798"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected llvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libLLVM");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libLLVM-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libLLVM-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libLLVM-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclang-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm-clang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm-clang-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm-clang-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm-vim-plugins");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/10");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libLLVM-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libLLVM-debuginfo-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libclang-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libclang-debuginfo-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"llvm-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"llvm-clang-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"llvm-clang-debuginfo-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"llvm-clang-devel-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"llvm-debuginfo-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"llvm-debugsource-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"llvm-devel-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"llvm-devel-debuginfo-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"llvm-vim-plugins-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libLLVM-32bit-3.3-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libLLVM-debuginfo-32bit-3.3-6.7.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libLLVM / libLLVM-32bit / libLLVM-debuginfo / etc");
}
