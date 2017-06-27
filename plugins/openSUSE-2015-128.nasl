#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-128.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81304);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/31 04:37:06 $");

  script_cve_id("CVE-2014-5351", "CVE-2014-5352", "CVE-2014-9421", "CVE-2014-9422", "CVE-2014-9423");

  script_name(english:"openSUSE Security Update : krb5 (openSUSE-2015-128)");
  script_summary(english:"Check for the openSUSE-2015-128 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"krb5 was updated to fix five security issues.

These security issues were fixed :

  - CVE-2014-5351: current keys returned when randomizing
    the keys for a service principal (bnc#897874) 

  - CVE-2014-5352: An authenticated attacker could cause a
    vulnerable application (including kadmind) to crash or
    to execute arbitrary code (bnc#912002).

  - CVE-2014-9421: An authenticated attacker could cause
    kadmind or other vulnerable server application to crash
    or to execute arbitrary code (bnc#912002).

  - CVE-2014-9422: An attacker who possess the key of a
    particularly named principal (such as 'kad/root') could
    impersonate any user to kadmind and perform
    administrative actions as that user (bnc#912002).

  - CVE-2014-9423: An attacker could attempt to glean
    sensitive information from the four or eight bytes of
    uninitialized data output by kadmind or other libgssrpc
    server application. Because MIT krb5 generally sanitizes
    memory containing krb5 keys before freeing it, it is
    unlikely that kadmind would leak Kerberos key
    information, but it is not impossible (bnc#912002).

This non-security issue was fixed :

  - Work around replay cache creation race (bnc#898439)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=897874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=898439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912002"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-kdb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-kdb-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-otp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-pkinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/12");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"krb5-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-client-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-client-debuginfo-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-debuginfo-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-debugsource-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-devel-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-mini-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-mini-debuginfo-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-mini-debugsource-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-mini-devel-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-plugin-kdb-ldap-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-plugin-kdb-ldap-debuginfo-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-plugin-preauth-otp-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-plugin-preauth-otp-debuginfo-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-plugin-preauth-pkinit-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-server-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"krb5-server-debuginfo-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"krb5-32bit-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"krb5-debuginfo-32bit-1.12.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"krb5-devel-32bit-1.12.2-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-mini / krb5-mini-debuginfo / krb5-mini-debugsource / etc");
}
