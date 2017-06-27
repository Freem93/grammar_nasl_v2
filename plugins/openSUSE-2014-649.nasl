#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-649.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79224);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_cve_id("CVE-2014-8354", "CVE-2014-8355", "CVE-2014-8562");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-SU-2014:1396-1)");
  script_summary(english:"Check for the openSUSE-2014-649 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ImageMagick was updated to fix three security issues. &#9; These
security issues were fixed :

  - Out-of-bounds memory access in PCX parser
    (CVE-2014-8355).

  - Out-of-bounds memory access in resize code
    (CVE-2014-8354).

  - Out-of-bounds memory error in DCM decode
    (CVE-2014-8562)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=903204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=903216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=903638"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"ImageMagick-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ImageMagick-debuginfo-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ImageMagick-debugsource-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ImageMagick-devel-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ImageMagick-extra-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ImageMagick-extra-debuginfo-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libMagick++-devel-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libMagick++5-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libMagick++5-debuginfo-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libMagickCore5-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libMagickCore5-debuginfo-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libMagickWand5-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libMagickWand5-debuginfo-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"perl-PerlMagick-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"perl-PerlMagick-debuginfo-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libMagickCore5-32bit-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libMagickCore5-debuginfo-32bit-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libMagickWand5-32bit-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libMagickWand5-debuginfo-32bit-6.7.8.8-4.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ImageMagick-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ImageMagick-debuginfo-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ImageMagick-debugsource-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ImageMagick-devel-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ImageMagick-extra-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ImageMagick-extra-debuginfo-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libMagick++-6_Q16-2-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libMagick++-6_Q16-2-debuginfo-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libMagick++-devel-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libMagickCore-6_Q16-1-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libMagickWand-6_Q16-1-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-PerlMagick-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-PerlMagick-debuginfo-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libMagick++-6_Q16-2-32bit-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libMagick++-6_Q16-2-debuginfo-32bit-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-32bit-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-32bit-6.8.6.9-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-debuginfo-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-debugsource-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-devel-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-extra-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-extra-debuginfo-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagick++-6_Q16-5-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagick++-6_Q16-5-debuginfo-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagick++-devel-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagickCore-6_Q16-2-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagickCore-6_Q16-2-debuginfo-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagickWand-6_Q16-2-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagickWand-6_Q16-2-debuginfo-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-PerlMagick-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-PerlMagick-debuginfo-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagick++-6_Q16-5-32bit-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagick++-6_Q16-5-debuginfo-32bit-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-2-32bit-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-2-debuginfo-32bit-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-2-32bit-6.8.9.8-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-2-debuginfo-32bit-6.8.9.8-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-debuginfo / ImageMagick-debugsource / etc");
}
