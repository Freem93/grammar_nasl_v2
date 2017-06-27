#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-87.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75410);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-7069");

  script_name(english:"openSUSE Security Update : ack (openSUSE-SU-2014:0142-1)");
  script_summary(english:"Check for the openSUSE-2014-87 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to ack 2.12: fixes potential remote code
    execution via per-project .ackrc files [bnc#855340]
    [CVE-2013-7069]

  - prevents the --pager, --regex and --output options from
    being used from project-level ackrc files, preventing
    possible code execution when using ack through malicious
    files

  - --pager, --regex and --output options may still be used
    from the global /etc/ackrc, your own private ~/.ackrc,
    the ACK_OPTIONS environment variable, and of course from
    the command line.

  - Now ignores Eclipse .metadata directory.

  - includes changes form 2.11_02 :

  - upstream source mispackaging fix

  - includes changes from 2.11_01

  - Fixed a race condition in t/file-permission.t that was
    causing failures if tests were run in parallel.

  - includes changes from 2.10 :

  - Add --perltest for *.t files

  - Added Matlab support

  - More compatibility fixes for Perl 5.8.8.

  - includes changes from 2.08

  - ack now ignores CMake's build/cache directories by
    default

  - Add shebang matching for --lua files

  - Add documentation for --ackrc

  - Add Elixir filetype

  - Add --cathy option

  - Add some helpful debugging tips when an invalid option
    is found

  - Ignore PDF files by default, because Perl will detect
    them as text

  - Ignore .gif, .jpg, .jpeg and .png files. They won't
    normally be selected, but this is an optimization so
    that ack doesn't have to open them to know

  - Ack's colorizing of output would get confused with
    multiple sets of parentheses

  - Ack would get confused when trying to colorize the
    output in DOS-format files

  - includes changes from 2.05_01

  - We now ignore the node_modules directories created by
    npm

  - --pager without an argument implies --pager=$PAGER

  - --perl now recognizes Plack-style .psgi files

  - Added filetypes for Coffescript, JSON, LESS, and Sass.

  - Command-line options now override options set in ackrc
    files

  - ACK_PAGER and ACK_PAGER_COLOR now work as advertised.

  - Fix a bug resulting in uninitialized variable warnings
    when more than one capture group was specified in the
    search pattern

  - Make sure ack is happy to build and test under cron and
    other console-less environments.

  - packaging changes :

  - run more rests with IO::Pty

  - refresh ack-ignore-osc.patch for upstream changes

  - update project URL

  - port changes from devel:languages:perl ack by
    daxim@cpan.org :

  - correct metadata: licence, CPAN download, homepage

  - unset forced prefix - let Perl configuration and
    toolchain determine the prefix/install_base which will
    DTRT

  - bash completion is gone, remove dead code

  - modified patches :

  - ack-ignore-osc.patch adjust for upstream source changes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-01/msg00094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=855340"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ack packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-App-Ack");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/20");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"ack-2.12-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-App-Ack-2.12-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ack / perl-App-Ack");
}
