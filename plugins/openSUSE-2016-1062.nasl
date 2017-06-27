#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1062.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93390);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2016-5746");

  script_name(english:"openSUSE Security Update : libstorage (openSUSE-2016-1062)");
  script_summary(english:"Check for the openSUSE-2016-1062 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libstorage fixes the following issues :

  - Use stdin, not tmp files for passwords (bsc#986971,
    CVE-2016-5746)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986971"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libstorage packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstorage-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstorage-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstorage-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstorage-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstorage-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstorage-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstorage-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstorage-testsuite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstorage6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstorage6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-storage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-storage-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-storage-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/09");
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

if ( rpm_check(release:"SUSE42.1", reference:"libstorage-debugsource-2.25.35.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libstorage-devel-2.25.35.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libstorage-python-2.25.35.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libstorage-python-debuginfo-2.25.35.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libstorage-ruby-2.25.35.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libstorage-ruby-debuginfo-2.25.35.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libstorage-testsuite-2.25.35.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libstorage-testsuite-debuginfo-2.25.35.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libstorage6-2.25.35.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libstorage6-debuginfo-2.25.35.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"yast2-storage-3.1.71-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"yast2-storage-debuginfo-3.1.71-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"yast2-storage-debugsource-3.1.71-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"yast2-storage-devel-3.1.71-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libstorage-debugsource / libstorage-devel / libstorage-python / etc");
}
