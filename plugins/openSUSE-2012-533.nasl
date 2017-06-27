#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-533.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74724);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-3456");

  script_name(english:"openSUSE Security Update : calligra (openSUSE-SU-2012:1061-1)");
  script_summary(english:"Check for the openSUSE-2012-533 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fix buffer overflow in MS Word ODF filter among other non-security
related bugs.

Also a version update to 2.4.3 happened :

  - Words :

  - Always show vertical scroll bar to avoid race condition
    (kde#301076)

  - Do not save with an attribue that makes LibreOffice and
    OpenOffice crash (kde#298689 )

  - Kexi :

  - Fixed import from csv when &ldquo;Start at Line&rdquo;
    value changed (kde#302209)

  - Set limit to 255 characters for Text type (VARCHAR)
    (kde#301277 and 301136)

  + - Remove limits for Text data type, leave as option
    (kde#301277)

  - Fixed data saving when focus policy for one of widgets
    is NoFocus (kde#301109)

  - Krita :

  - Read and set the resolution for psd images

  - Charts :

  - Fix load/save styles of all shapes
    (title,subtitle,axistitles,footer,etc.)

  - Lines in the chart should be displayed (kde#271771)

  - Combined Bar and Line Charts only show bars (Trendlines
    not supported) (kde#288537)

  - Load/save chart type for each dataset (kde#271771 and
    288537)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-08/msg00041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774534"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected calligra packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-braindump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-braindump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-flow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-flow-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-karbon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kexi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kexi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kexi-mssql-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kexi-mssql-driver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kexi-mysql-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kexi-mysql-driver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kexi-postgresql-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kexi-postgresql-driver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kexi-spreadsheet-import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kexi-spreadsheet-import-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kexi-xbase-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kexi-xbase-driver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-krita");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-krita-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kthesaurus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-kthesaurus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-plan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-plan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-sheets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-sheets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-stage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-stage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-words");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calligra-words-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"calligra-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-braindump-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-braindump-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-debugsource-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-devel-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-flow-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-flow-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-karbon-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-karbon-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kexi-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kexi-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kexi-mssql-driver-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kexi-mssql-driver-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kexi-mysql-driver-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kexi-mysql-driver-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kexi-postgresql-driver-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kexi-postgresql-driver-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kexi-spreadsheet-import-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kexi-spreadsheet-import-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kexi-xbase-driver-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kexi-xbase-driver-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-krita-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-krita-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kthesaurus-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-kthesaurus-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-plan-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-plan-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-sheets-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-sheets-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-stage-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-stage-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-tools-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-tools-debuginfo-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-words-2.4.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"calligra-words-debuginfo-2.4.3-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "calligra");
}
