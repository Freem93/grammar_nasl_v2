#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2011-88.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74536);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-4318");

  script_name(english:"openSUSE Security Update : dovecot20 (openSUSE-2011-88)");
  script_summary(english:"Check for the openSUSE-2011-88 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In proxy mode dovecot did not verify that the SSL certificate of the
remote actually matched the server name.

Dovecot was updated to version 2.0.16 which fixes the problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732050"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot20 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot20-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot20-backend-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot20-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot20-backend-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot20-backend-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot20-backend-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot20-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot20-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot20-fts-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot20-fts-solr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/08");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"dovecot20-2.0.16-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"dovecot20-backend-mysql-2.0.16-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"dovecot20-backend-mysql-debuginfo-2.0.16-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"dovecot20-backend-pgsql-2.0.16-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"dovecot20-backend-pgsql-debuginfo-2.0.16-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"dovecot20-backend-sqlite-2.0.16-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"dovecot20-backend-sqlite-debuginfo-2.0.16-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"dovecot20-debuginfo-2.0.16-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"dovecot20-debugsource-2.0.16-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"dovecot20-devel-2.0.16-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"dovecot20-fts-solr-2.0.16-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"dovecot20-fts-solr-debuginfo-2.0.16-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot20 / dovecot20-backend-mysql / etc");
}
