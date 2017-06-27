#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-261.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97281);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/24 14:02:38 $");

  script_cve_id("CVE-2017-5930");

  script_name(english:"openSUSE Security Update : postfixadmin (openSUSE-2017-261)");
  script_summary(english:"Check for the openSUSE-2017-261 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"postfixadmin was updated to 3.0.2 to fix the following issues :

  - PostfixAdmin 3.0.2 :

  - SECURITY: don't allow to delete protected aliases
    (CVE-2017-5930, boo#1024211)

  - fix VacationHandler for PostgreSQL

  - AliasHandler: restrict mailbox subquery to allowed and
    specified domains to improve performance on setups with
    lots of mailboxes

  - allow switching between dovecot:* password schemes while
    still accepting passwords hashed using the previous
    dovecot:* scheme

  - FetchmailHandler: use a valid date as default for 'date'

  - fix date formatting in non-english languages when using
    PostgreSQL

  - various small fixes

  - PostfixAdmin 3.0 :

  - add sqlite backend option

  - add configurable smtp helo (CONF['smtp_client'])

  - new translation: ro (Romanian)

  - language update: tw, cs, de

  - fix escaping in gen_show_status() (could be used to DOS
    list-virtual by creating a mail address with special
    chars)

  - add CSRF protection for POST requests

  - list.tpl: base edit/editactive/delete links in list.tpl
    on $RAW_item to avoid double escaping, and fix some
    corner cases

  - fix db_quota_text() for postgresql (concat() vs. ||)

  - change default date for 'created' and 'updated' columns
    from 0000-00-00 (which causes problems with MySQL strict
    mode) to 2000-01-01

  - allow punicode even in TLDs

  - update Smarty to 3.1.29

  - add checks to login.php and cli to ensure database
    layout is up to date

  - whitelist '-1' as valid value for postfixadmin-cli

  - don't stripslashes() the password in pacrypt

  - various small bugfixes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024211"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postfixadmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postfixadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/21");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"postfixadmin-3.0.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postfixadmin-3.0.2-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postfixadmin");
}
