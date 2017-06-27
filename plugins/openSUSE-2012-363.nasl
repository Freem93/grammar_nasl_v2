#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-363.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74665);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-3356", "CVE-2012-3357");

  script_name(english:"openSUSE Security Update : viewvc (openSUSE-SU-2012:0831-1)");
  script_summary(english:"Check for the openSUSE-2012-363 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to 1.1.15 (bnc#768680) :

  - security fix: complete authz support for remote SVN
    views (CVE-2012-3356)

  - security fix: log msg leak in SVN revision view with
    unreadable copy source (CVE-2012-3357)

Additionally the following non-security issues have been addressed :

  - fix several instances of incorrect information in remote
    SVN views

  - increase performance of some revision metadata lookups
    in remote SVN views

  - fix RSS feed regression introduced in 1.1.14

  - fix annotation of svn files with non-URI-safe paths

  - handle file:/// Subversion rootpaths as local roots

  - fix bug caused by trying to case-normalize anon
    usernames

  - speed up log handling by reusing tokenization results

  - add support for custom review log markup rules

  - fix svndbadmin failure on deleted paths under Subversion
    1.7

  - fix annotation of files in svn roots with non-URI-safe
    paths

  - fix stray annotation warning in markup display of images

  - more gracefully handle attempts to display binary
    content

  - fix path display in patch and certain diff views

  - fix broken cvsdb glob searching

  - allow svn revision specifiers to have leading r's

  - allow environmental override of configuration location

  - fix exception HTML-escaping non-string data under WSGI

  - add links to root logs from roots view

  - use Pygments lexer-guessing functionality

  - add supplements for apache2/subversion-server"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-07/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768680"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected viewvc package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:viewvc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/26");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"viewvc-1.1.15-6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"viewvc-1.1.15-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "viewvc");
}
