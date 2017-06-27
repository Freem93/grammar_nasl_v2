#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update gwenview-3080.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(49754);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/13 19:49:34 $");

  script_cve_id("CVE-2010-2575");

  script_name(english:"openSUSE Security Update : gwenview (openSUSE-SU-2010:0691-1)");
  script_summary(english:"Check for the gwenview-3080 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a heap-based overflow in okular. The RLE
decompression in the TranscribePalmImageToJPEG() function can be
exploited to execute arbitrary code with user privileges by providing
a crafted PDF file. (CVE-2010-2575)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-10/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=634743"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gwenview packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gwenview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gwenview-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-gwenview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-kcolorchooser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-kgamma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-kio_kamera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-kolourpaint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-kruler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-ksnapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-okular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-okular-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdegraphics4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdcraw7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdcraw7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkexiv2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkexiv2-7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkipi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkipi5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkipi5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksane0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.1", reference:"gwenview-1.4.2-116.50.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"gwenview-lang-1.4.2-116.50.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-gwenview-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-kcolorchooser-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-kgamma-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-kio_kamera-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-kolourpaint-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-kruler-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-ksnapshot-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-okular-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-okular-devel-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdegraphics4-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libkdcraw7-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libkdcraw7-devel-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libkexiv2-7-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libkexiv2-7-devel-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libkipi-devel-0.1.6-1.64.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libkipi5-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libkipi5-devel-4.1.3-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libksane0-4.1.3-4.8.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gwenview / gwenview-lang / kde4-gwenview / kde4-kcolorchooser / etc");
}
