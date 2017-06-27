#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update finch-5557.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75830);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-1091", "CVE-2011-4601", "CVE-2011-4602", "CVE-2011-4603");
  script_osvdb_id(74921, 77749, 77750, 77751);

  script_name(english:"openSUSE Security Update : finch (openSUSE-SU-2012:0066-1)");
  script_summary(english:"Check for the finch-5557 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Remote users could crash pidgin via ICQ, SILC, XMPP and Yahoo
protocols (CVE-2011-4601, CVE-2011-4603, CVE-2011-4602,
CVE-2011-1091)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-01/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=736147"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected finch packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/19");
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

if ( rpm_check(release:"SUSE11.4", reference:"finch-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"finch-debuginfo-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"finch-devel-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libpurple-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libpurple-debuginfo-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libpurple-devel-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libpurple-lang-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libpurple-meanwhile-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libpurple-meanwhile-debuginfo-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libpurple-tcl-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libpurple-tcl-debuginfo-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pidgin-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pidgin-debuginfo-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pidgin-debugsource-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pidgin-devel-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pidgin-evolution-2.7.10-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pidgin-evolution-debuginfo-2.7.10-4.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-lang / etc");
}
