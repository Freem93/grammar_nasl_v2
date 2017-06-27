#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ImageMagick-967.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40165);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 19:49:34 $");

  script_cve_id("CVE-2009-1882");

  script_name(english:"openSUSE Security Update : ImageMagick (ImageMagick-967)");
  script_summary(english:"Check for the ImageMagick-967 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of ImageMagick fixes an integer overflow in the
XMakeImage() function that allowed remote attackers to cause a
denial-of-service and possibly the execution of arbitrary code via a
crafted TIFF file. (CVE-2009-1882)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=507728"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"ImageMagick-6.4.3.6-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ImageMagick-devel-6.4.3.6-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ImageMagick-extra-6.4.3.6-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libMagick++-devel-6.4.3.6-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libMagick++1-6.4.3.6-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libMagickCore1-6.4.3.6-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libMagickWand1-6.4.3.6-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"perl-PerlMagick-6.4.3.6-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libMagickCore1-32bit-6.4.3.6-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libMagickWand1-32bit-6.4.3.6-5.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
