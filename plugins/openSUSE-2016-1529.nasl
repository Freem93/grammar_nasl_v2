#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1529.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96176);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/29 14:22:37 $");

  script_name(english:"openSUSE Security Update : irc-otr (openSUSE-2016-1529)");
  script_summary(english:"Check for the openSUSE-2016-1529 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This updates irc-otr to version 1.0.2 and fixes the following issues :

  - Only the first line of messages transmitted via OTR
    sessions was a PRIVMSG and additional data was sent as a
    raw command to the IRC server (boo#1016942).

  - Detect the libotr-emitted HTML-formatted init string and
    replace it with a description customized for IRC and
    irssi-otr."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016942"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected irc-otr packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irc-otr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-otr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-otr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"irc-otr-debugsource-1.0.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"irssi-otr-1.0.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"irssi-otr-debuginfo-1.0.2-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irc-otr-debugsource / irssi-otr / irssi-otr-debuginfo");
}
