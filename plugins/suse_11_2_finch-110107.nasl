#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update finch-3783.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(53717);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/06/13 20:00:35 $");

  script_cve_id("CVE-2010-4528");

  script_name(english:"openSUSE Security Update : finch (openSUSE-SU-2011:0021-1)");
  script_summary(english:"Check for the finch-3783 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A NULL pointer dereference DoS has been fixed in pidgin. CVE-2010-4528
has been assigned to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-01/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=661497"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected finch packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-otr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"finch-2.7.9-1.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"finch-devel-2.7.9-1.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpurple-2.7.9-1.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpurple-devel-2.7.9-1.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpurple-lang-2.7.9-1.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpurple-meanwhile-2.7.9-1.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpurple-mono-2.7.9-1.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpurple-tcl-2.7.9-1.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pidgin-2.7.9-1.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pidgin-devel-2.7.9-1.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pidgin-otr-3.2.0-142.4.5") ) flag++;

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
