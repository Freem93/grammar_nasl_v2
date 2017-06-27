#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update GraphicsMagick-5276.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(33378);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2008-1096", "CVE-2008-1097");

  script_name(english:"openSUSE 10 Security Update : GraphicsMagick (GraphicsMagick-5276)");
  script_summary(english:"Check for the GraphicsMagick-5276 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GraphicsMagick is affected by two security problems :

CVE-2008-1096: Buffer overflow in the handling of XCF files
CVE-2008-1097: Heap buffer overflow in the handling of PCX files"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected GraphicsMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"GraphicsMagick-1.1.7-35.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"GraphicsMagick-c++-1.1.7-35.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"GraphicsMagick-c++-devel-1.1.7-35.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"GraphicsMagick-devel-1.1.7-35.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"perl-GraphicsMagick-1.1.7-35.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"GraphicsMagick-1.1.8-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"GraphicsMagick-devel-1.1.8-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libGraphicsMagick++-devel-1.1.8-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libGraphicsMagick++1-1.1.8-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libGraphicsMagick1-1.1.8-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libGraphicsMagickWand0-1.1.8-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"perl-GraphicsMagick-1.1.8-20.4") ) flag++;

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
