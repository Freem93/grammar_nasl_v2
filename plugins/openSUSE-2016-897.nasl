#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-897.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92538);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/07/25 14:38:52 $");

  script_cve_id("CVE-2012-3534");

  script_name(english:"openSUSE Security Update : gnugk (openSUSE-2016-897)");
  script_summary(english:"Check for the openSUSE-2016-897 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"gnugk was updated fix security issues and bugs.

The following issues were fixed :

  - CVE-2012-3534: denial of service via lots of connections
    (boo#777486)

The new version 4.2 of gnuk also fixes a number of bugs and contains
other improvements and fixes. The new library h323plus was added to
the distribution as a dependency."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=777486"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnugk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnugk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnugk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnugk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:h323plus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:h323plus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libh323-1_26_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libh323-1_26_5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/25");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"gnugk-4.2-139.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gnugk-debuginfo-4.2-139.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gnugk-debugsource-4.2-139.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"h323plus-debugsource-1.26.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"h323plus-devel-1.26.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libh323-1_26_5-1.26.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libh323-1_26_5-debuginfo-1.26.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gnugk-4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gnugk-debuginfo-4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gnugk-debugsource-4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"h323plus-debugsource-1.26.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"h323plus-devel-1.26.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libh323-1_26_5-1.26.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libh323-1_26_5-debuginfo-1.26.5-2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnugk / gnugk-debuginfo / gnugk-debugsource / h323plus-debugsource / etc");
}
