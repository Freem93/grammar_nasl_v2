#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-634.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86284);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/07 14:48:41 $");

  script_cve_id("CVE-2015-4335");

  script_name(english:"openSUSE Security Update : redis (openSUSE-2015-634)");
  script_summary(english:"Check for the openSUSE-2015-634 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"redis was updated to version 2.8.22 (boo#934048) to fix a LUA sandbox
update. (CVE-2015-4335) Details can be found on
http://benmmurphy.github.io/blog/2015/06/04/redis-eval-lua-sandbox-esc
ape/

For the other changes see in the package:
/usr/share/doc/packages/redis/00-RELEASENOTES"
  );
  # http://benmmurphy.github.io/blog/2015/06/04/redis-eval-lua-sandbox-escape/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d07c07d6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934048"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected redis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:redis-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:redis-debugsource");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"redis-2.8.22-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"redis-debuginfo-2.8.22-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"redis-debugsource-2.8.22-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipa_hbac-devel-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipa_hbac0-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipa_hbac0-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libnfsidmap-sss-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libnfsidmap-sss-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_idmap-devel-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_idmap0-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_idmap0-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_nss_idmap-devel-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_nss_idmap0-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_nss_idmap0-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_simpleifp-devel-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_simpleifp0-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_simpleifp0-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_sudo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsss_sudo-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-ipa_hbac-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-ipa_hbac-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-sss_nss_idmap-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-sss_nss_idmap-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-sssd-config-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-sssd-config-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"redis-2.8.22-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"redis-debuginfo-2.8.22-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"redis-debugsource-2.8.22-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-ad-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-ad-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-dbus-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-dbus-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-debugsource-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-ipa-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-ipa-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-krb5-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-krb5-common-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-krb5-common-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-krb5-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-ldap-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-ldap-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-proxy-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-proxy-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-tools-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-tools-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-wbclient-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-wbclient-debuginfo-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"sssd-wbclient-devel-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"sssd-32bit-1.12.2-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"sssd-debuginfo-32bit-1.12.2-3.11.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "redis / redis-debuginfo / redis-debugsource / libipa_hbac-devel / etc");
}
