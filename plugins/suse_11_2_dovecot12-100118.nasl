#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update dovecot12-1811.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(44053);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/06/13 20:00:35 $");

  script_cve_id("CVE-2009-3897");

  script_name(english:"openSUSE Security Update : dovecot12 (dovecot12-1811)");
  script_summary(english:"Check for the dovecot12-1811 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dovecot created the configured 'base_dir' (/var/run/dovecot) with mode
0777 if it didn't exist, therefore allowing local users to mess with
e.g. the authentication socket (CVE-2009-3897).

Note that /var/run/dovecot is part of the dovecot rpm with proper
permission settings. Therefor dovecot is not vulnerable in the default
configuration as shipped on openSUSE."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=none"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557184"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot12 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-backend-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-fts-lucene");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.2", reference:"dovecot12-1.2.9-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"dovecot12-backend-mysql-1.2.9-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"dovecot12-backend-pgsql-1.2.9-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"dovecot12-backend-sqlite-1.2.9-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"dovecot12-devel-1.2.9-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"dovecot12-fts-lucene-1.2.9-0.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot12 / dovecot12-backend-mysql / dovecot12-backend-pgsql / etc");
}
