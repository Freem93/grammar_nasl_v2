#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2011-35.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74523);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-3594");

  script_name(english:"openSUSE Security Update : pidgin (openSUSE-2011-35)");
  script_summary(english:"Check for the openSUSE-2011-35 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:"specially crafted SILC messages could crash libpurple (CVE-2011-3594)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-evolution-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/29");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"finch-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"finch-debuginfo-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"finch-devel-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-branding-upstream-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-debuginfo-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-devel-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-lang-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-meanwhile-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-meanwhile-debuginfo-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-tcl-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-tcl-debuginfo-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"pidgin-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"pidgin-debuginfo-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"pidgin-debugsource-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"pidgin-devel-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"pidgin-evolution-2.10.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"pidgin-evolution-debuginfo-2.10.0-8.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-debuginfo / finch-devel / libpurple / etc");
}
