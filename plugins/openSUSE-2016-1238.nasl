#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1238.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94312);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/27 13:13:07 $");

  script_cve_id("CVE-2014-0249");

  script_name(english:"openSUSE Security Update : sssd (openSUSE-2016-1238)");
  script_summary(english:"Check for the openSUSE-2016-1238 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for sssd fixes one security issue and three bugs.

The following vulnerability was fixed :

  - CVE-2014-0249: Incorrect expansion of group membership
    when encountering a non-POSIX group. (bsc#880245)

The following non-security fixes were also included :

  - Prevent crashes of statically linked binaries using
    getpwuid when sssd is used and nscd is turned off or has
    caching disabled. (bsc#993582)

  - Add logrotate configuration to prevent log files from
    growing too large when running with debug mode enabled.
    (bsc#1004220)

  - Order sudo rules by the same logic used by the native
    LDAP support from sudo. (bsc#1002973)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=880245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993582"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-ipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-ipa_hbac-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-sss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-sss_nss_idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-sssd-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-sssd-config-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-proxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libipa_hbac-devel-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libipa_hbac0-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libipa_hbac0-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsss_idmap-devel-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsss_idmap0-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsss_idmap0-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsss_nss_idmap-devel-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsss_nss_idmap0-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsss_nss_idmap0-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsss_sudo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsss_sudo-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-ipa_hbac-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-ipa_hbac-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-sss_nss_idmap-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-sss_nss_idmap-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-sssd-config-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-sssd-config-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-ad-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-ad-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-debugsource-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-ipa-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-ipa-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-krb5-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-krb5-common-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-krb5-common-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-krb5-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-ldap-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-ldap-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-proxy-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-proxy-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-tools-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"sssd-tools-debuginfo-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"sssd-32bit-1.11.5.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"sssd-debuginfo-32bit-1.11.5.1-16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac-devel / libipa_hbac0 / libipa_hbac0-debuginfo / etc");
}
