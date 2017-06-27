#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1205.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94215);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/24 13:56:00 $");

  script_name(english:"openSUSE Security Update : roundcubemail (openSUSE-2016-1205)");
  script_summary(english:"Check for the openSUSE-2016-1205 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for roundcubemail to 1.1.6 fixes several issues
(boo#1001856).

These security issues were fixed :

  - Fix XSS issue in href attribute on area tag

  - Wash position:fixed style in HTML mail for better
    security

These non-security issues were fixed :

  - Searching in both contacts and groups when LDAP
    addressbook with group_filters option is used

  - Use contact_search_name format in popup on results in
    compose contacts search

  - Fix missing localization of HTML editor when assets_dir
    != INSTALL_PATH

  - Fix handling of blockquote tags with mixed case on
    html2text conversion

  - Fix message list multi-select/deselect issue

  - Fix bug where contact search menu fields where always
    unchecked in Larry skin

  - Fix bug where message list columns could be in wrong
    order after column drag-n-drop and list sorting

  - Don't create multipart/alternative messages with empty
    text/plain part

  - Fix error causing empty INBOX listing in Firefox when
    using an URL with user:password specified"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001856"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"roundcubemail-1.1.6-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "roundcubemail");
}
