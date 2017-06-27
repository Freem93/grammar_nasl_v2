#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-668.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74770);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2012-4405");

  script_name(english:"openSUSE Security Update : ghostscript (openSUSE-SU-2012:1289-1)");
  script_summary(english:"Check for the openSUSE-2012-668 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security issue was fixed in ghostscript :

Multiple integer underflows in the icmLut_allocate function in
International Color Consortium (ICC) Format library (icclib), as used
in Ghostscript 9.06 and Argyll Color Management System, allow remote
attackers to cause a denial of service (crash) and possibly execute
arbitrary code via a crafted (1) PostScript or (2) PDF file with
embedded images, which triggers a heap-based buffer overflow. NOTE:
this issue is also described as an array index error."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-10/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779700"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-fonts-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-fonts-rus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-fonts-std");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-ijs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-library");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-library-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-library-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpprint-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpprint-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/25");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"ghostscript-devel-9.00-4.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ghostscript-fonts-other-9.00-4.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ghostscript-fonts-rus-9.00-4.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ghostscript-fonts-std-9.00-4.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ghostscript-ijs-devel-9.00-4.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ghostscript-library-9.00-4.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ghostscript-library-debuginfo-9.00-4.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ghostscript-library-debugsource-9.00-4.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ghostscript-x11-9.00-4.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ghostscript-x11-debuginfo-9.00-4.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libgimpprint-4.2.7-334.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libgimpprint-debuginfo-4.2.7-334.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libgimpprint-devel-4.2.7-334.48.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript");
}
