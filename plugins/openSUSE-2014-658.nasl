#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-658.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79225);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/07/08 14:36:37 $");

  script_cve_id("CVE-2014-0249");

  script_name(english:"openSUSE Security Update : sssd (openSUSE-SU-2014:1407-1)");
  script_summary(english:"Check for the openSUSE-2014-658 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"sssd was updated to new upstream release 1.12.2 (bugfix release,
bnc#900159)

Changes :

  - Fixed a regression where the IPA provider did not fetch
    User Private Groups correctly

  - An important bug in the GPO access control which
    resulted in a wrong principal being used, was fixed.

  - Several new options are available for deployments that
    need to restrict a certain PAM service from connecting
    to a certain SSSD domain. For more details, see the
    description of pam_trusted_users and pam_public_domains
    options in the sssd.conf(5) man page and the domains
    option in the pam_sss(8) man page.

  - When SSSD is acting as an IPA client in setup with
    trusted AD domains, it is able to return group members
    or full group memberships for users from trusted AD
    domains.

  - Support for the 'views' feature of IPA.

  - The GPO access control was further enhanced to allow the
    access control decisions while offline and map the
    Windows logon rights onto Linux PAM services.

  - The SSSD now ships a plugin for the rpc.idmapd daemon,
    sss_rpcidmapd(5).

  - A MIT Kerberos localauth plugin was added to SSSD. This
    plugin helps translating principals to user names in
    IPA-AD trust scenarios, allowing the krb5.conf
    configuration to be less complex.

  - A libwbclient plugin implementation is now part of the
    SSSD. The main purpose is to map Active Directory users
    and groups identified by their SID to POSIX users and
    groups for the file-server use-case.

  - Active Directory users ca nnow use their User Logon Name
    to log in.

  - The sss_cache tool was enhanced to allow invalidating
    the SSH host keys.

  - Groups without full POSIX information can now be used to
    enroll group membership (CVE-2014-0249).

  - Detection of transition from offline to online state was
    improved, resulting in fewer timeouts when SSSD is
    offline.

  - The Active Directory provider now correctly detects
    Windows Server 2012 R2. Previous versions would fall
    back to the slower non-AD path with 2012 R2.

  - Several other bugs related to deployments where SSSD is
    acting as an AD client were fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00047.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900159"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnfsidmap-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnfsidmap-sss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_simpleifp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_simpleifp0-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-dbus-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-wbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-wbclient-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-wbclient-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libipa_hbac-devel-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipa_hbac0-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipa_hbac0-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libnfsidmap-sss-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libnfsidmap-sss-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_idmap-devel-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_idmap0-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_idmap0-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_nss_idmap-devel-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_nss_idmap0-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_nss_idmap0-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_simpleifp-devel-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_simpleifp0-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_simpleifp0-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_sudo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_sudo-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-ipa_hbac-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-ipa_hbac-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-sss_nss_idmap-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-sss_nss_idmap-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-sssd-config-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-sssd-config-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-ad-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-ad-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-dbus-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-dbus-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-debugsource-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-ipa-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-ipa-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-krb5-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-krb5-common-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-krb5-common-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-krb5-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-ldap-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-ldap-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-proxy-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-proxy-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-tools-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-tools-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-wbclient-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-wbclient-debuginfo-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-wbclient-devel-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"sssd-32bit-1.12.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"sssd-debuginfo-32bit-1.12.2-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sssd");
}
