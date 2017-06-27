#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-608.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91278);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2016-4348");

  script_name(english:"openSUSE Security Update : librsvg (openSUSE-2016-608)");
  script_summary(english:"Check for the openSUSE-2016-608 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This librsvg update to version 2.40.15 fixes the following issues :

Security issues fixed :

  - CVE-2016-4348: DoS parsing SVGs with circular
    definitions _rsvg_css_normalize_font_size() function
    (boo#977986)

Bugs fixed :

  - Actually scale the image if required, regression fix
    from upstream git (bgo#760262).

  - Fixed bgo#759084: Don't crash when filters don't
    actually exist.

  - Updated our autogen.sh to use modern autotools.

  - Fixed bgo#761728: Memory leak in the
    PrimitiveComponentTransfer filter.

  - Added basic support for the 'baseline-shift' attribute
    in text objects (bgo#340047).

  - Fixed some duplicate logic when rendering paths
    (bgo#749415).

  - Rewrote the markers engine (bgo#685906, bgo#760180).

  - Refactoring of the test harness to use Glib's gtest
    infrastructure, instead of using home-grown machinery.
    Tests can simply be put as SVG files in the
    tests/subdirectories; it is not necessary to list them
    explicitly in some text file.

  - Gzipped SVGs now work if read from streams.

  - References to objects/filters/URIs/etc. are now handled
    lazily. Also, there is a general-purpose cycle detector
    so malformed SVGs don't cause infinite loops.

  - Removed parsing of Adobe blend modes; they were not
    implemented, anyway.

  - Add project files for building on Visual Studio
    (bgo#753555).

  - Added an '--export-id' option to rsvg-convert(1). This
    lets you select a single object to export, for example,
    to pick out a group from a multi-part drawing. Note that
    this is mostly useful for PNG output right now; for SVG
    output we don't preserve many attributes which could be
    useful in the extracted version. Doing this properly
    requires an internal 'output to SVG' backend instead of
    just telling Cairo to render to SVG."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977986"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected librsvg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsvg-view");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsvg-view-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Rsvg-2_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/20");
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

if ( rpm_check(release:"SUSE13.2", reference:"gdk-pixbuf-loader-rsvg-2.40.15-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gdk-pixbuf-loader-rsvg-debuginfo-2.40.15-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"librsvg-2-2-2.40.15-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"librsvg-2-2-debuginfo-2.40.15-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"librsvg-debugsource-2.40.15-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"librsvg-devel-2.40.15-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rsvg-view-2.40.15-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rsvg-view-debuginfo-2.40.15-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-Rsvg-2_0-2.40.15-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-32bit-2.40.15-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-debuginfo-32bit-2.40.15-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"librsvg-2-2-32bit-2.40.15-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"librsvg-2-2-debuginfo-32bit-2.40.15-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gdk-pixbuf-loader-rsvg-2.40.15-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gdk-pixbuf-loader-rsvg-debuginfo-2.40.15-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"librsvg-2-2-2.40.15-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"librsvg-2-2-debuginfo-2.40.15-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"librsvg-debugsource-2.40.15-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"librsvg-devel-2.40.15-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"rsvg-view-2.40.15-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"rsvg-view-debuginfo-2.40.15-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"typelib-1_0-Rsvg-2_0-2.40.15-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-32bit-2.40.15-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-debuginfo-32bit-2.40.15-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"librsvg-2-2-32bit-2.40.15-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"librsvg-2-2-debuginfo-32bit-2.40.15-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf-loader-rsvg / gdk-pixbuf-loader-rsvg-32bit / etc");
}
