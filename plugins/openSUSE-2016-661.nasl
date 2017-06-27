#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-661.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91408);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/06/01 15:53:42 $");

  script_cve_id("CVE-2015-7995");

  script_name(english:"openSUSE Security Update : libxslt (openSUSE-2016-661)");
  script_summary(english:"Check for the openSUSE-2016-661 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libxslt fixes the following issues :

  - CVE-2015-7995: A type confusion in preprocessing
    attributes was fixed [boo#952474]."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=952474"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxslt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/01");
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

if ( rpm_check(release:"SUSE13.2", reference:"libxslt-debugsource-1.1.28-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxslt-devel-1.1.28-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxslt-python-1.1.28-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxslt-python-debuginfo-1.1.28-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxslt-python-debugsource-1.1.28-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxslt-tools-1.1.28-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxslt-tools-debuginfo-1.1.28-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxslt1-1.1.28-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxslt1-debuginfo-1.1.28-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxslt-devel-32bit-1.1.28-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxslt1-32bit-1.1.28-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxslt1-debuginfo-32bit-1.1.28-7.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxslt-python / libxslt-python-debuginfo / etc");
}
