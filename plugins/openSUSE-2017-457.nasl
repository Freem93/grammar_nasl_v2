#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-457.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99295);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/14 18:50:29 $");

  script_cve_id("CVE-2017-2640");
  script_xref(name:"IAVB", value:"2017-B-0029");

  script_name(english:"openSUSE Security Update : pidgin (openSUSE-2017-457)");
  script_summary(english:"Check for the openSUSE-2017-457 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pidgin to version 2.12.0 fixes the following issues :

This security issue was fixed :

  - CVE-2017-2640: Out of bounds memory read in
    purple_markup_unescape_entity (boo#1028835).

These non-security issues were fixed :

  + libpurple :

  - Fix the use of uninitialised memory if running
    non-debug-enabled versions of glib.

  - Update AIM dev and dist ID's to new ones that were
    assigned by AOL.

  - TLS certificate verification now uses SHA-256 checksums.

  - Fix the SASL external auth for Freenode (boo#1009974).

  - Remove the MSN protocol plugin. It has been unusable and
    dormant for some time.

  - Remove the Mxit protocol plugin. The service was closed
    at the end ofSeptember 2016.

  - Remove the MySpaceIM protocol plugin. The service has
    been defunct for a long time (pidgin.im#15356).

  - Remove the Yahoo! protocol plugin. Yahoo has completely
    reimplemented their protocol, so this version is no
    longer operable as of August 5th, 2016.

  - Remove the Facebook (XMPP) account option. According to
    https://developers.facebook.com/docs/chat the XMPP Chat
    API service ended April 30th, 2015.

  - Fix gnutls certificate validation errors that mainly
    affected Google.

  + General :

  - Replace instances of d.pidgin.im with
    developer.pidgin.im and update the urls to use https
    (pidgin.im#17036).

  + IRC :

  - Fix an issue of messages being silently cut off at 500
    characters. Large messages are now split into parts and
    sent one by one (pidgin.im#4753)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://developers.facebook.com/docs/chat"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-branding-openSUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-sametime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-sametime-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"finch-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"finch-debuginfo-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"finch-devel-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpurple-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpurple-branding-openSUSE-42.2-3.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpurple-branding-upstream-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpurple-debuginfo-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpurple-devel-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpurple-lang-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpurple-plugin-sametime-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpurple-plugin-sametime-debuginfo-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpurple-tcl-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpurple-tcl-debuginfo-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pidgin-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pidgin-debuginfo-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pidgin-debugsource-2.12.0-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pidgin-devel-2.12.0-8.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpurple-branding-openSUSE / finch / finch-debuginfo / finch-devel / etc");
}
