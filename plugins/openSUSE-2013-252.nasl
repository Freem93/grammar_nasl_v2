#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-252.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74944);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2012-3438");
  script_osvdb_id(84323);

  script_name(english:"openSUSE Security Update : GraphicsMagick (openSUSE-SU-2013:0536-1)");
  script_summary(english:"Check for the openSUSE-2013-252 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GraphicsMagick was updated to fix integer overflows in the _png_malloc
functions (CVE-2012-3438)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00102.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773612"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected GraphicsMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/18");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"GraphicsMagick-1.3.12-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"GraphicsMagick-debuginfo-1.3.12-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"GraphicsMagick-debugsource-1.3.12-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"GraphicsMagick-devel-1.3.12-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libGraphicsMagick++-devel-1.3.12-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libGraphicsMagick++3-1.3.12-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libGraphicsMagick++3-debuginfo-1.3.12-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libGraphicsMagick3-1.3.12-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libGraphicsMagick3-debuginfo-1.3.12-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libGraphicsMagickWand2-1.3.12-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libGraphicsMagickWand2-debuginfo-1.3.12-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"perl-GraphicsMagick-1.3.12-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"perl-GraphicsMagick-debuginfo-1.3.12-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"GraphicsMagick-1.3.15-14.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"GraphicsMagick-debuginfo-1.3.15-14.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"GraphicsMagick-debugsource-1.3.15-14.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"GraphicsMagick-devel-1.3.15-14.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libGraphicsMagick++-devel-1.3.15-14.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libGraphicsMagick++3-1.3.15-14.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libGraphicsMagick++3-debuginfo-1.3.15-14.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libGraphicsMagick3-1.3.15-14.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libGraphicsMagick3-debuginfo-1.3.15-14.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libGraphicsMagickWand2-1.3.15-14.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libGraphicsMagickWand2-debuginfo-1.3.15-14.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-GraphicsMagick-1.3.15-14.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-GraphicsMagick-debuginfo-1.3.15-14.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"GraphicsMagick-1.3.17-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"GraphicsMagick-debuginfo-1.3.17-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"GraphicsMagick-debugsource-1.3.17-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"GraphicsMagick-devel-1.3.17-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libGraphicsMagick++-devel-1.3.17-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libGraphicsMagick++3-1.3.17-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libGraphicsMagick++3-debuginfo-1.3.17-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libGraphicsMagick3-1.3.17-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libGraphicsMagick3-debuginfo-1.3.17-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libGraphicsMagickWand2-1.3.17-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libGraphicsMagickWand2-debuginfo-1.3.17-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"perl-GraphicsMagick-1.3.17-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"perl-GraphicsMagick-debuginfo-1.3.17-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GraphicsMagick");
}
