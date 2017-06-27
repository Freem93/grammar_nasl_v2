#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-687.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75132);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2012-6121", "CVE-2013-5645");
  script_bugtraq_id(57849, 61976);
  script_osvdb_id(90175, 90177, 96575, 96576);

  script_name(english:"openSUSE Security Update : roundcubemail (openSUSE-SU-2013:1420-1)");
  script_summary(english:"Check for the openSUSE-2013-687 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"roundcubemail was updated to version 0.9.3 (bnc#837436)
(CVE-2013-5645)

  - Optimized UI behavior for touch devices

  - Fix setting refresh_interval to 'Never' in Preferences

  - Fix purge action in folder manager

  - Fix base URL resolving on attribute values with no
    quotes

  - Fix wrong handling of links with '|' character

  - Fix colorspace issue on image conversion using
    ImageMagick?

  - Fix XSS vulnerability when saving HTML signatures

  - Fix XSS vulnerability when editing a message 'as new' or
    draft

  - Fix rewrite rule in .htaccess

  - Fix detecting Turkish language in ISO-8859-9 encoding

  - Fix identity-selection using Return-Path headers

  - Fix parsing of links with ... in URL

  - Fix compose priority selector when opening in new window

  - Fix bug where signature wasn't changed on identity
    selection when editing a draft

  - Fix IMAP SETMETADATA parameters quoting

  - Fix 'could not load message' error on valid empty
    message body

  - Fix handling of message/rfc822 attachments on message
    forward and edit

  - Fix parsing of square bracket characters in IMAP
    response strings

  - Don't clear References and in-Reply-To when a message is
    'edited as new'

  - Fix messages list sorting with THREAD=REFS

  - Remove deprecated (in PHP 5.5) PREG /e modifier usage

  - Fix empty messages list when register_globals is enabled

  - Fix so valid and set date.timezone is not required by
    installer checks

  - Canonize boolean ini_get() results

  - Fix so install do not fail when one of DB driver checks
    fails but other drivers exist

  - Fix so exported vCard specifies encoding in
    v3-compatible format

  - Update to version 0.9.2

  - Fix image thumbnails display in print mode

  - Fix height of message headers block

  - Fix timeout issue on drag&drop uploads

  - Fix default sorting of threaded list when THREAD=REFS
    isn't supported

  - Fix list mode switch to 'List' after saving list
    settings in Larry skin

  - Fix error when there's no writeable addressbook source

  - Fix zipdownload plugin issue with filenames charset

  - Fix so non-inline images aren't skipped on forward

  - Fix 'null' instead of empty string on messages list in
    IE10

  - Fix legacy options handling

  - Fix so bounces addresses in Sender headers are skipped
    on Reply-All

  - Fix bug where serialized strings were truncated in
    PDO::quote()

  - Fix displaying messages with invalid self-closing HTML
    tags

  - Fix PHP warning when responding to a message with many
    Return-Path headers

  - Fix unintentional compose window resize

  - Fix performance regression in text wrapping function

  - Fix connection to posgtres db using unix socket

  - Fix handling of comma when adding contact from contacts
    widget

  - Fix bug where a message was opened in both preview pane
    and new window on double-click

  - Fix fatal error when xdebug.max_nesting_level was
    exceeded in rcube_washtml

  - Fix PHP warning in html_table::set_row_attribs() in PHP
    5.4

  - Fix invalid option selected in default_font selector
    when font is unset

  - Fix displaying contact with ID divisible by 100 in sql
    addressbook

  - Fix browser warnings on PDF plugin detection

  - Fix fatal error when parsing UUencoded messages

  - Update to version 0.9.1

  - a lot of bugfixes and smaller improvements
    (http://trac.roundcube.net/wiki/Changelog)

  - Update to version 0.9.0

  - Improved rendering of forwarded and attached messages

  - Optionally display and compose email messages a new
    windows

  - Unified UI for message view and composition

  - Show sender photos from contacts in email view

  - Render thumbnails for image attachments

  - Download all attachments as zip archive (using the
    zipdownload plugin)

  - Forward multiple emails as attachments

  - CSV import for contacts"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-09/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://trac.roundcube.net/wiki/Changelog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=837436"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"roundcubemail-0.9.3-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"roundcubemail-0.9.3-1.8.1") ) flag++;

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
