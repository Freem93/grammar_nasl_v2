#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-6.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96254);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/03 14:55:09 $");

  script_cve_id("CVE-2016-1241", "CVE-2016-1242");

  script_name(english:"openSUSE Security Update : GNU Health and it's dependencies (openSUSE-2017-6)");
  script_summary(english:"Check for the openSUSE-2017-6 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides version 3.0.5 of GNU Health including several
fixes and improvements.

  - Update to ICD10 version 2016.

  - Fix error when printing prescription using review dates.

  - Fix error on summary report when no date of birth is
    assigned to the person.

Additionally the following dependencies have been updated :

tryton :

  - Update to 3.8.12.

  - Sanitize path in file open. (boo#1016886, CVE-2016-1242)

  - Prevent read of user password hash. (boo#1016885,
    CVE-2016-1241)

trytond :

  - Update to 3.8.9.

  - Sanitize path in file open. (boo#1016886, CVE-2016-1242)

  - Prevent read of user password hash. (boo#1016885,
    CVE-2016-1241)

trytond_account :

  - Update to 3.8.5.

trytond_account_invoice :

  - Update to 3.8.4.

trytond_stock :

  - Update to 3.8.4.

trytond_stock_lot :

  - Update to 3.8.1.

porteus :

  - Update to 3.8.5."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016886"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected GNU Health and it's dependencies packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnuhealth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proteus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tryton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:trytond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:trytond_account");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:trytond_account_invoice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:trytond_stock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:trytond_stock_lot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"gnuhealth-3.0.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proteus-3.8.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tryton-3.8.12-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"trytond-3.8.9-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"trytond_account-3.8.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"trytond_account_invoice-3.8.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"trytond_stock-3.8.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"trytond_stock_lot-3.8.1-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnuhealth / trytond_account / trytond_account_invoice / etc");
}
