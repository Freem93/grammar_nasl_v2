#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-241.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97114);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/13 20:45:10 $");

  script_name(english:"openSUSE Security Update : irssi (openSUSE-2017-241)");
  script_summary(english:"Check for the openSUSE-2017-241 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The IRC textmode client irssi was updated to version 1.0.1 to fix bugs
and security issues.

irssi 1.0.1 :

  - Fix Perl compilation in object dir

  - Fix incorrect HELP SERVER example

  - Correct memory leak in /OP and /VOICE

  - Fix regression that broke second level completion

  - Correct missing NULL termination in perl_parse
    boo#1023638

  - Sync broken mail.pl script

  - Prevent a memory leak during the processing of the SASL
    response boo#1023637

irssi 1.0.0 :

  - irssiproxy can now forward all tags through a single
    port.

  - The kill buffer now remembers consecutive kills. New
    bindings were added: yank_next_cutbuffer and
    append_next_kill.

  - autolog_ignore_targets and activity_hide_targets learn a
    new syntax tag/* and * to ignore whole networks or
    everything.

  - hilight got a -matchcase flag to hilight case
    sensitively.

  - Display TLS connection information upon connect. You can
    disable this by setting tls_verbose_connect to FALSE

  - Certificate pinning for TLS certificates

  - /names and $[&hellip;] now uses utf8 string operations.

  - New setting completion_nicks_match_case

  - /channel /server /network now support modify subcommand.

  - New option sasl_disconnect_on_failure to disconnect when
    SASL log-in failed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023638"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected irssi packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"irssi-1.0.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"irssi-debuginfo-1.0.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"irssi-debugsource-1.0.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"irssi-devel-1.0.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"irssi-1.0.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"irssi-debuginfo-1.0.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"irssi-debugsource-1.0.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"irssi-devel-1.0.1-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irssi / irssi-debuginfo / irssi-debugsource / irssi-devel");
}
