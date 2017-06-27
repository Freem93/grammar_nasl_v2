#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-600.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91270);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2011-5326", "CVE-2014-9762", "CVE-2014-9763", "CVE-2014-9764", "CVE-2014-9771", "CVE-2016-3993", "CVE-2016-3994", "CVE-2016-4024");

  script_name(english:"openSUSE Security Update : imlib2 (openSUSE-2016-600)");
  script_summary(english:"Check for the openSUSE-2016-600 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This imlib2 update to version 1.4.9 fixes the following issues :

Security issues fixed :

  - CVE-2011-5326: divide by 0 when drawing an ellipse of
    height 1 (boo#974202)

  - CVE-2014-9762: segmentation fault on images without
    colormap (boo#963796)

  - CVE-2014-9764: segmentation fault when opening
    specifically crafted input (boo#963797)

  - CVE-2014-9763: division-by-zero crashes when opening
    images (boo#963800)

  - CVE-2014-9771: exploitable integer overflow in
    _imlib_SaveImage (boo#974854)

  - CVE-2016-3994: imlib2/evas Potential DOS in giflib
    loader (boo#973759)

  - CVE-2016-3993: off by 1 Potential DOS (boo#973761)

  - CVE-2016-4024: integer overflow resulting in
    insufficient heap allocation (boo#975703)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975703"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imlib2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imlib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imlib2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imlib2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imlib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imlib2-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imlib2-filters-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imlib2-loaders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imlib2-loaders-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libImlib2-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libImlib2-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"imlib2-1.4.9-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"imlib2-debuginfo-1.4.9-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"imlib2-debugsource-1.4.9-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"imlib2-devel-1.4.9-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"imlib2-filters-1.4.9-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"imlib2-filters-debuginfo-1.4.9-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"imlib2-loaders-1.4.9-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"imlib2-loaders-debuginfo-1.4.9-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libImlib2-1-1.4.9-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libImlib2-1-debuginfo-1.4.9-17.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imlib2 / imlib2-debuginfo / imlib2-debugsource / imlib2-devel / etc");
}
