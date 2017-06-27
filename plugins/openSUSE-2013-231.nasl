#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-231.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74934);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-0271", "CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274");
  script_bugtraq_id(57951, 57952, 57954);

  script_name(english:"openSUSE Security Update : pidgin (openSUSE-SU-2013:0511-1)");
  script_summary(english:"Check for the openSUSE-2013-231 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Pidgin was updated to 2.10.7 to fix various security issues and the
bug that IRC did not work at all in 12.3.

Changes :

  - Add pidgin-irc-sasl.patch: link irc module to SASL.
    Allows the IRC module to be loaded (bnc#806975).

  - Update to version 2.10.7 (bnc#804742) :

  + Alien hatchery :

  - No changes

  + General :

  - The configure script will now exit with status 1 when
    specifying invalid protocol plugins using the

    --with-static-prpls and --with-dynamic-prpls arguments.
    (pidgin.im#15316)

  + libpurple :

  - Fix a crash when receiving UPnP responses with
    abnormally long values. (CVE-2013-0274)

  - Don't link directly to libgcrypt when building with
    GnuTLS support. (pidgin.im#15329)

  - Fix UPnP mappings on routers that return empty
    <URLBase/> elements in their response. (pidgin.im#15373)

  - Tcl plugin uses saner, race-free plugin loading.

  - Fix the Tcl signals-test plugin for savedstatus-changed.
    (pidgin.im#15443)

  + Pidgin :

  - Make Pidgin more friendly to non-X11 GTK+, such as
    MacPorts' +no_x11 variant.

  + Gadu-Gadu :

  - Fix a crash at startup with large contact list. Avatar
    support for buddies will be disabled until 3.0.0.
    (pidgin.im#15226, pidgin.im#14305)

  + IRC :

  - Support for SASL authentication. (pidgin.im#13270)

  - Print topic setter information at channel join.
    (pidgin.im#13317)

  + MSN :

  - Fix SSL certificate issue when signing into MSN for some
    users.

  - Fix a crash when removing a user before its icon is
    loaded. (pidgin.im#15217)

  + MXit :

  - Fix a bug where a remote MXit user could possibly
    specify a local file path to be written to.
    (CVE-2013-0271)

  - Fix a bug where the MXit server or a man-in-the-middle
    could potentially send specially crafted data that could
    overflow a buffer and lead to a crash or remote code
    execution. (CVE-2013-0272)

  - Display farewell messages in a different colour to
    distinguish them from normal messages.

  - Add support for typing notification.

  - Add support for the Relationship Status profile
    attribute.

  - Remove all reference to Hidden Number.

  - Ignore new invites to join a GroupChat if you're already
    joined, or still have a pending invite.

  - The buddy's name was not centered vertically in the
    buddy-list if they did not have a status-message or mood
    set.

  - Fix decoding of font-size changes in the markup of
    received messages.

  - Increase the maximum file size that can be transferred
    to 1 MB.

  - When setting an avatar image, no longer downscale it to
    96x96.

  + Sametime :

  - Fix a crash in Sametime when a malicious server sends us
    an abnormally long user ID. (CVE-2013-0273)

  + Yahoo! :

  - Fix a double-free in profile/picture loading code.
    (pidgin.im#15053)

  - Fix retrieving server-side buddy aliases.
    (pidgin.im#15381)

  + Plugins :

  - The Voice/Video Settings plugin supports using the sndio
    GStreamer backends. (pidgin.im#14414)

  - Fix a crash in the Contact Availability Detection
    plugin. (pidgin.im#15327)

  - Make the Message Notification plugin more friendly to
    non-X11 GTK+, such as MacPorts' +no_x11 variant.

  + Windows-Specific Changes :

  - Compile with secure flags (pidgin.im#15290)

  - Installer downloads GTK+ Runtime and Debug Symbols more
    securely. (pidgin.im#15277)

  - Updates to a number of dependencies, some of which have
    security related fixes. (pidgin.im#14571,
    pidgin.im#15285, pidgin.im#15286) . ATK 1.32.0-2 . Cyrus
    SASL 2.1.25 . expat 2.1.0-1 . freetype 2.4.10-1 .
    gettext 0.18.1.1-2 . Glib 2.28.8-1 . libpng 1.4.12-1 .
    libxml2 2.9.0-1 . NSS 3.13.6 and NSPR 4.9.2 . Pango
    1.29.4-1 . SILC 1.1.10 . zlib 1.2.5-2

  - Patch libmeanwhile (sametime library) to fix crash.
    (pidgin.im#12637)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806975"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/11");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"finch-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"finch-debuginfo-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"finch-devel-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-branding-upstream-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-debuginfo-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-devel-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-lang-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-meanwhile-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-meanwhile-debuginfo-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-tcl-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-tcl-debuginfo-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-debuginfo-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-debugsource-2.10.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-devel-2.10.7-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pidgin");
}
