#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-58.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80989);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/11 13:51:33 $");

  script_cve_id("CVE-2014-9587");

  script_name(english:"openSUSE Security Update : roundcubemail (openSUSE-SU-2015:0116-1)");
  script_summary(english:"Check for the openSUSE-2015-58 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"roundcubemail was updated to 1.0.4 fixing bugs and security issues.

Changes :

  - Disable TinyMCE contextmenu plugin as there are more
    cons than pros in using it (#1490118)

  - Fix bug where show_real_foldernames setting wasn't
    honored on compose page (#1490153)

  - Fix issue where Archive folder wasn't protected in
    Folder Manager (#1490154)

  - Fix compatibility with PHP 5.2. in rcube_imap_generic
    (#1490115)

  - Fix setting flags on servers with no PERMANENTFLAGS
    response (#1490087)

  - Fix regression in SHAA password generation in ldap
    driver of password plugin (#1490094)

  - Fix displaying of HTML messages with absolutely
    positioned elements in Larry skin (#1490103)

  - Fix font style display issue in HTML messages with
    styled <span> elements (#1490101)

  - Fix download of attachments that are part of TNEF
    message (#1490091)

  - Fix handling of uuencoded messages if messages_cache is
    enabled (#1490108)

  - Fix handling of base64-encoded attachments with extra
    spaces (#1490111)

  - Fix handling of UNKNOWN-CTE response, try do decode
    content client-side (#1490046)

  - Fix bug where creating subfolders in shared folders
    wasn't possible without ACL extension (#1490113)

  - Fix reply scrolling issue with text mode and start
    message below the quote (#1490114)

  - Fix possible issues in skin/skin_path config handling
    (#1490125)

  - Fix lack of delimiter for recipient addresses in
    smtp_log (#1490150)

  - Fix generation of Blowfish-based password hashes
    (#1490184)

  - Fix bugs where CSRF attacks were still possible on some
    requests (CVE-2014-9587)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2015-01/msg00056.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=913095"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"roundcubemail-1.0.4-4.1") ) flag++;

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
