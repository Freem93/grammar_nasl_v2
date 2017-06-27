#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-995.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93067);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/13 20:45:10 $");

  script_cve_id("CVE-2015-2181", "CVE-2015-8864", "CVE-2016-4069");

  script_name(english:"openSUSE Security Update : roundcubemail (openSUSE-2016-995)");
  script_summary(english:"Check for the openSUSE-2016-995 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for roundcubemail fixes the following vulnerabilities :

  - CVE-2015-8864: XSS issue in SVG images handling
    (boo#976988)

  - CVE-2015-2181: issue in DBMail driver of password plugin

  - CVE-2016-4069: Cross-site request forgery in download
    URLs (boo#976988) Roundcubemail was also updated to
    1.1.5, fixing the following bugs :

  - Plugin API: Add html2text hook

  - Plugin API: Added addressbook_export hook

  - Fix missing emoticons on html-to-text conversion

  - Fix random 'access to this resource is secured against
    CSRF' message at logout

  - Fix missing language name in 'Add to Dictionary' request
    in HTML mode

  - Enable use of TLSv1.1 and TLSv1.2 for IMAP

  - Fix bug where Archive/Junk buttons were not active after
    page jump with select=all mode

  - Fix bug in long recipients list parsing for cases where
    recipient name contained @-char

  - Fix additional_message_headers plugin compatibility with
    Mail_Mime >= 1.9

  - Hide DSN option in Preferences when smtp_server is not
    used

  - newmail_notifier: Refactor desktop notifications

  - Fix so contactlist_fields option can be set via config
    file

  - Fix so SPECIAL-USE assignments are forced only until
    user sets special folders

  - Fix performance in reverting order of THREAD result

  - Fix converting mail addresses with @www. into mailto
    links"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976988"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.1", reference:"roundcubemail-1.1.5-9.1") ) flag++;

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
