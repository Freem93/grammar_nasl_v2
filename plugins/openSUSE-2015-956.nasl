#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-956.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87629);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-7758");

  script_name(english:"openSUSE Security Update : gummi (openSUSE-2015-956)");
  script_summary(english:"Check for the openSUSE-2015-956 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gummi fixes the following issues :

  - CVE-2015-7758: Fix an exploitable issue caused by gummi
    setting predictable file names in /tmp; patch taken from
    debian patch tracker and submitted upstream
    (bnc#949682)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949682"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gummi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gummi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gummi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gummi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gummi-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"gummi-0.6.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gummi-debuginfo-0.6.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gummi-debugsource-0.6.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gummi-0.6.5-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gummi-debuginfo-0.6.5-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gummi-debugsource-0.6.5-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gummi-0.7.1-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gummi-debuginfo-0.7.1-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gummi-debugsource-0.7.1-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gummi-lang-0.7.1-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gummi / gummi-debuginfo / gummi-debugsource / gummi-lang");
}
