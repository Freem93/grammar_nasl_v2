#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-526.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85174);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/03 13:36:17 $");

  script_cve_id("CVE-2015-1545", "CVE-2015-1546");

  script_name(english:"openSUSE Security Update : openldap2 (openSUSE-2015-526)");
  script_summary(english:"Check for the openSUSE-2015-526 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenLDAP was updated to fix two security issues and one bug.

The following vulnerabilities were fixed :

  - CVE-2015-1546: slapd crash in valueReturnFilter cleanup
    (bnc#916914)

  - CVE-2015-1545: slapd crashes on search with deref
    control and empty attr list (bnc#916897)

The following non-security bug was fixed :

  - boo#905959: Prevent connection-0 (internal connection)
    from show up in the monitor backend"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=916897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=916914"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:compat-libldap-2_3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:compat-libldap-2_3-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-2_4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-2_4-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-2_4-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-2_4-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-meta-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-client-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-devel-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/03");
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

if ( rpm_check(release:"SUSE13.1", reference:"libldap-2_4-2-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libldap-2_4-2-debuginfo-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-back-meta-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-back-meta-debuginfo-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-back-perl-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-back-perl-debuginfo-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-back-sql-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-back-sql-debuginfo-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-client-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-client-debuginfo-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-client-debugsource-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-debuginfo-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-debugsource-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-devel-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openldap2-devel-static-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libldap-2_4-2-32bit-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libldap-2_4-2-debuginfo-32bit-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"openldap2-devel-32bit-2.4.33-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"compat-libldap-2_3-0-2.3.37-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"compat-libldap-2_3-0-debuginfo-2.3.37-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libldap-2_4-2-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libldap-2_4-2-debuginfo-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-back-meta-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-back-meta-debuginfo-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-back-perl-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-back-perl-debuginfo-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-back-sql-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-back-sql-debuginfo-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-client-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-client-debuginfo-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-client-debugsource-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-debuginfo-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-debugsource-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-devel-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openldap2-devel-static-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libldap-2_4-2-32bit-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libldap-2_4-2-debuginfo-32bit-2.4.39-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"openldap2-devel-32bit-2.4.39-8.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libldap-2_4-2 / libldap-2_4-2-32bit / libldap-2_4-2-debuginfo / etc");
}
