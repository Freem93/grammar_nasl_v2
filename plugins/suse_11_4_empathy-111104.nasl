#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update empathy-5376.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75823);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:32 $");

  script_cve_id("CVE-2011-3635");
  script_osvdb_id(76485);

  script_name(english:"openSUSE Security Update : empathy (openSUSE-SU-2011:1257-1)");
  script_summary(english:"Check for the empathy-5376 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Insufficient quoting of nick names allowed attackers to inject
arbitrary html (CVE-2011-3635)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-11/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=727003"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected empathy packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:empathy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:empathy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:empathy-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:empathy-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-sendto-plugin-empathy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-sendto-plugin-empathy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/04");
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

if ( rpm_check(release:"SUSE11.4", reference:"empathy-2.32.2-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"empathy-debuginfo-2.32.2-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"empathy-debugsource-2.32.2-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"empathy-lang-2.32.2-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nautilus-sendto-plugin-empathy-2.32.2-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nautilus-sendto-plugin-empathy-debuginfo-2.32.2-7.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "empathy / empathy-lang / nautilus-sendto-plugin-empathy / etc");
}
