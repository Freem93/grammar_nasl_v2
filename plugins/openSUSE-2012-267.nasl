#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-267.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74618);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-2132");
  script_osvdb_id(81862);

  script_name(english:"openSUSE Security Update : epiphany / libsoup (openSUSE-SU-2012:0609-1)");
  script_summary(english:"Check for the openSUSE-2012-267 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libsoup considered all ssl connections as trusted even if no CA
certificates were configured."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-05/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758431"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected epiphany / libsoup packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:epiphany-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:epiphany-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:epiphany-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:epiphany-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:epiphany-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoup-2_4-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoup-2_4-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoup-2_4-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoup-2_4-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoup-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoup-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoup-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:midori");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:midori-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:midori-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:midori-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:midori-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/28");
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

if ( rpm_check(release:"SUSE11.4", reference:"epiphany-2.30.6-14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"epiphany-branding-upstream-2.30.6-14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"epiphany-debuginfo-2.30.6-14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"epiphany-debugsource-2.30.6-14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"epiphany-devel-2.30.6-14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"epiphany-lang-2.30.6-14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsoup-2_4-1-2.32.2-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsoup-2_4-1-debuginfo-2.32.2-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsoup-debugsource-2.32.2-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsoup-devel-2.32.2-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"midori-0.3.0-7.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"midori-debuginfo-0.3.0-7.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"midori-debugsource-0.3.0-7.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"midori-devel-0.3.0-7.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"midori-lang-0.3.0-7.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsoup-2_4-1-32bit-2.32.2-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsoup-2_4-1-debuginfo-32bit-2.32.2-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsoup-devel-32bit-2.32.2-3.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "epiphany / epiphany-branding-upstream / epiphany-debuginfo / etc");
}
