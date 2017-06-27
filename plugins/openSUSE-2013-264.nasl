#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-264.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74947);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-0287");

  script_name(english:"openSUSE Security Update : sssd (openSUSE-SU-2013:0559-1)");
  script_summary(english:"Check for the openSUSE-2013-264 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"When SSSD is configured as an Active Directory client by using the new
Active Directory provider or equivalent configuration of the LDAP
provider, the Simple Access Provider does not handle access control
correctly. If any groups are specified with the simple_deny_groups
option, the group members are permitted access. (CVE-2013-0287)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00115.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809153"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-ipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-ipa_hbac-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-sssd-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-sssd-config-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ipa-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ipa-provider-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/21");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libipa_hbac-devel-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libipa_hbac0-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libipa_hbac0-debuginfo-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsss_idmap-devel-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsss_idmap0-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsss_idmap0-debuginfo-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsss_sudo-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsss_sudo-debuginfo-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-ipa_hbac-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-ipa_hbac-debuginfo-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-sssd-config-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-sssd-config-debuginfo-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sssd-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sssd-debuginfo-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sssd-debugsource-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sssd-ipa-provider-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sssd-ipa-provider-debuginfo-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sssd-tools-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sssd-tools-debuginfo-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"sssd-32bit-1.9.4-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"sssd-debuginfo-32bit-1.9.4-1.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sssd");
}
