#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ImageMagick-4543.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27604);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4987", "CVE-2007-4988");

  script_name(english:"openSUSE 10 Security Update : ImageMagick (ImageMagick-4543)");
  script_summary(english:"Check for the ImageMagick-4543 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of ImageMagick fixes several vulnerabilities.

  - CVE-2007-4985: infinite loop while parsing images

  - CVE-2007-4986: integer overflows that can lead to code
    execution

  - CVE-2007-4987: one-byte buffer overflow that can lead to
    code execution (SLES8- and SLES9-based products are not
    affected)

  - CVE-2007-4988: integer overflows that can lead to code
    execution"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-Magick++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-Magick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"ImageMagick-6.2.5-16.26") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ImageMagick-Magick++-6.2.5-16.26") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ImageMagick-Magick++-devel-6.2.5-16.26") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ImageMagick-devel-6.2.5-16.26") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"perl-PerlMagick-6.2.5-16.26") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ImageMagick-6.3.0.0-27.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ImageMagick-Magick++-6.3.0.0-27.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ImageMagick-Magick++-devel-6.3.0.0-27.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ImageMagick-devel-6.3.0.0-27.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"perl-PerlMagick-6.3.0.0-27.8") ) flag++;

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
