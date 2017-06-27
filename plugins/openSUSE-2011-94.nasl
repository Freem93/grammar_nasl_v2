#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2011-94.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74539);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-4634");

  script_name(english:"openSUSE Security Update : phpMyAdmin (openSUSE-2011-94)");
  script_summary(english:"Check for the openSUSE-2011-94 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to 3.4.8

  - bug #3425230 [interface] enum data split at space char
    (more space to edit)

  - bug #3426840 [interface] ENUM/SET editor can't handle
    commas in values

  - bug #3427256 [interface] no links to browse/empty views
    and tables

  - bug #3430377 [interface] Deleted search results remain
    visible

  - bug #3428627 [import] ODS import ignores memory limits

  - bug #3426836 [interface] Visual column separation

  - bug #3428065 [parser] TRUE not recognized by parser

  + patch #3433770 [config] Make location of php-gettext
    configurable

  - patch #3430291 [import] Handle conflicts in some
    open_basedir situations

  - bug #3431427 [display] Dropdown results - setting NULL
    does not work

  - patch #3428764 [edit] Inline edit on multi-server
    configuration

  - patch #3437354 [core] Notice: Array to string conversion
    in PHP 5.4

  - [interface] When ShowTooltipAliasTB is true, VIEW is
    wrongly shown as the view name in main panel db
    Structure page

  - bug #3439292 [core] Fail to synchronize column with name
    of keyword

  - bug #3425156 [interface] Add column after drop

  - [interface] Avoid showing the password in phpinfo()'s
    output

  - bug #3441572 [GUI] 'newer version of phpMyAdmin' message
    not shown in IE8

  - bug #3407235 [interface] Entering the key through a
    lookup window does not reset NULL

  - [security] Self-XSS on database names (Synchronize), see
    PMASA-2011-18

  - [security] Self-XSS on database names
    (Operations/rename), see PMASA-2011-18

  - [security] Self-XSS on column type (Create index), see
    PMASA-2011-18

  - [security] Self-XSS on column type (table Search), see
    PMASA-2011-18

  - [security] Self-XSS on invalid query (table overview),
    see PMASA-2011-18"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=736772"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"phpMyAdmin-3.4.8-1.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
