#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-515.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74714);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_osvdb_id(84447, 84448, 84449, 84450, 84688);

  script_name(english:"openSUSE Security Update : opera (openSUSE-SU-2012:0992-1)");
  script_summary(english:"Check for the openSUSE-2012-515 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Opera was updated to version 12.1, fixing various bugs and security
issues.

http://www.opera.com/docs/changelogs/unix/1201/

Fixes and Stability Enhancements since Opera 12.00 General and User
Interface

Several general fixes and stability improvements

Website thumbnail memory usage improvements

Address bar inline auto-completion no longer prefers
shortest domain

Corrected an error that could occur after removing the
plugin wrapper

Resolved an issue where favicons were squeezed too much when
many tabs were open

Display and Scripting

Resolved an error with XHR transfers where content-type was
incorrectly determined

Improved handling of object literals with numeric duplicate
properties

Changed behavior of nested/chained comma expressions: now
expressing and compiling them as a list rather than a tree

Aligned behavior of the #caller property on function code
objects in ECMAScript 5 strict mode with the specification

Fixed an issue where input type=month would return an
incorrect value in its valueAsDate property

Resolved an issue with JSON.stringify() that could occur on
cached number conversion

Fixed a problem with redefining special properties using
Object.defineProperty()

Network and Site-Specific

Fixed an issue where loading would stop at 'Document 100%' but the
page would still be loading

tuenti.com: Corrected behavior when long content was
displayed

https://twitter.com Fixed an issue with secure transaction
errors

Fixed an issue with Google Maps Labs that occured when
compiling top-level loops inside strict evals

Corrected a problem that could occur with DISQUS

Fixed a crash occurring on Lenovo's 'Shop now' page

Corrected issues when calling window.console.log via a
variable at watch4you

Resolved an issue with Yahoo! chat

Mail, News, Chat

Resolved an issue where under certain conditions the mail panel would
continuously scroll up

Fixed a crash occurring when loading mail databases on
startup

Security

Re-fixed an issue where certain URL constructs could allow arbitrary
code execution, as reported by Andrey Stroganov; see our advisory

Fixed an issue where certain characters in HTML could
incorrectly be ignored, which could facilitate XSS attacks;
see our advisory

Fixed another issue where small windows could be used to
trick users into executing downloads as reported by Jordi
Chancel; see our advisory

Fixed an issue where an element's HTML content could be
incorrectly returned without escaping, bypassing some HTML
sanitizers; see our advisory

Fixed a low severity issue, details will be disclosed at a
later date

Advisory links from above: http://www.opera.com/support/kb/view/1016/
http://www.opera.com/support/kb/view/1026/
http://www.opera.com/support/kb/view/1027/
http://www.opera.com/support/kb/view/1025/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-08/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/docs/changelogs/unix/1201/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/1016/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/1025/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/1026/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/1027/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://twitter.com"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected opera packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/05");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"opera-12.01-25.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"opera-gtk-12.01-25.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"opera-kde4-12.01-25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"opera-12.01-19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"opera-gtk-12.01-19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"opera-kde4-12.01-19.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opera");
}
