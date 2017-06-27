#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-334.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97715);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/14 16:13:01 $");

  script_cve_id("CVE-2017-6410");

  script_name(english:"openSUSE Security Update : kdelibs4 / kio (openSUSE-2017-334)");
  script_summary(english:"Check for the openSUSE-2017-334 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kdelibs4, kio fixes the following issues :

  - CVE-2017-6410: Information Leak when accessing https
    when using a malicious PAC file (boo#1027520)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027520"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs4 / kio packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-doc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio-core-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio-core-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kio-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-apidocs-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-branding-upstream-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-core-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-core-debuginfo-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-debuginfo-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-debugsource-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-doc-debuginfo-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kio-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kio-core-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kio-core-debuginfo-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kio-debuginfo-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kio-debugsource-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kio-devel-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kio-devel-debuginfo-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kio-lang-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkde4-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkde4-debuginfo-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkde4-devel-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkdecore4-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkdecore4-debuginfo-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkdecore4-devel-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkdecore4-devel-debuginfo-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libksuseinstall-devel-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libksuseinstall1-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libksuseinstall1-debuginfo-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kio-32bit-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kio-core-32bit-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kio-core-debuginfo-32bit-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kio-debuginfo-32bit-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kio-devel-32bit-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kio-devel-debuginfo-32bit-5.21.0-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libkde4-32bit-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libkde4-debuginfo-32bit-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libkdecore4-32bit-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libkdecore4-debuginfo-32bit-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libksuseinstall1-32bit-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libksuseinstall1-debuginfo-32bit-4.14.18-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-apidocs-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-branding-upstream-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-core-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-core-debuginfo-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-debuginfo-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-debugsource-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-doc-debuginfo-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kio-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kio-core-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kio-core-debuginfo-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kio-debuginfo-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kio-debugsource-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kio-devel-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kio-devel-debuginfo-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kio-lang-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkde4-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkde4-debuginfo-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkde4-devel-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkdecore4-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkdecore4-debuginfo-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkdecore4-devel-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkdecore4-devel-debuginfo-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libksuseinstall-devel-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libksuseinstall1-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libksuseinstall1-debuginfo-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"kio-32bit-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"kio-core-32bit-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"kio-core-debuginfo-32bit-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"kio-debuginfo-32bit-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"kio-devel-32bit-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"kio-devel-debuginfo-32bit-5.26.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libkde4-32bit-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libkde4-debuginfo-32bit-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libkdecore4-32bit-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libkdecore4-debuginfo-32bit-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libksuseinstall1-32bit-4.14.25-5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libksuseinstall1-debuginfo-32bit-4.14.25-5.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs4-apidocs / kdelibs4 / kdelibs4-branding-upstream / etc");
}
