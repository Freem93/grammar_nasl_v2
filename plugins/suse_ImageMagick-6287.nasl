#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ImageMagick-6287.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(39498);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/13 20:11:35 $");

  script_cve_id("CVE-2009-1882");

  script_name(english:"openSUSE 10 Security Update : ImageMagick (ImageMagick-6287)");
  script_summary(english:"Check for the ImageMagick-6287 patch");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libWand10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/24");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"ImageMagick-6.3.5.10-2.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ImageMagick-devel-6.3.5.10-2.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ImageMagick-extra-6.3.5.10-2.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libMagick++-devel-6.3.5.10-2.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libMagick++10-6.3.5.10-2.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libMagick10-6.3.5.10-2.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libWand10-6.3.5.10-2.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"perl-PerlMagick-6.3.5.10-2.4") ) flag++;

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
