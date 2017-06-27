#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update apport-816.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40189);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/13 19:49:33 $");

  script_cve_id("CVE-2009-1295");

  script_name(english:"openSUSE Security Update : apport (apport-816)");
  script_summary(english:"Check for the apport-816 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The apport crash watcher / handler suite contains a cron job that
cleanes the world writeable /var/crash directory unsafely, allowing
local attackers to remove random files on the system. (CVE-2009-1295)

This update fixes this."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=495053"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apport packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apport-crashdb-opensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apport-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apport-retrace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"apport-0.114-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"apport-crashdb-opensuse-0.114-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"apport-gtk-0.114-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"apport-qt-0.114-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"apport-retrace-0.114-8.6.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apport");
}
