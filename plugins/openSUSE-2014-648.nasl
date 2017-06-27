#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-648.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79223);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/13 12:11:52 $");

  script_cve_id("CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3697", "CVE-2014-3698");

  script_name(english:"openSUSE Security Update : pidgin (openSUSE-SU-2014:1397-1)");
  script_summary(english:"Check for the openSUSE-2014-648 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to version 2.10.10 :

  + General :

  - Check the basic constraints extension when validating
    SSL/TLS certificates. This fixes a security hole that
    allowed a malicious man-in-the-middle to impersonate an
    IM server or any other https endpoint. This affected
    both the NSS and GnuTLS plugins (CVE-2014-3694,
    boo#902495).

  - Allow and prefer TLS 1.2 and 1.1 when using the NSS
    plugin for SSL (im#15909).

  + libpurple3 compatibility :

  - Encrypted account passwords are preserved until the new
    one is set.

  - Fix loading Google Talk and Facebook XMPP accounts.

  + Windows-Specific Changes: Don't allow overwriting
    arbitrary files on the file system when the user
    installs a smiley theme via drag-and-drop
    (CVE-2014-3697).

  + Finch: Fix build against Python 3 (im#15969).

  + Gadu-Gadu: Updated internal libgadu to version 1.12.0.

  + Groupwise: Fix potential remote crash parsing server
    message that indicates that a large amount of memory
    should be allocated (CVE-2014-3696, boo#902410).

  + IRC: Fix a possible leak of unencrypted data when using
    /me command with OTR (im#15750).

  + MXit: Fix potential remote crash parsing a malformed
    emoticon response (CVE-2014-3695, boo#902409).

  + XMPP :

  - Fix potential information leak where a malicious XMPP
    server and possibly even a malicious remote user could
    create a carefully crafted XMPP message that causes
    libpurple to send an XMPP message containing arbitrary
    memory (CVE-2014-3698, boo#902408).

  - Fix Facebook XMPP roster quirks (im#15041, im#15957).

  + Yahoo: Fix login when using the GnuTLS library for TLS
    connections (im#16172, boo#874606).

  - Drop pidgin-gstreamer1.patch: causes crashes and Video
    still does not work (boo#853038). Drop BuildRequires
    conditions switching to GStreamer 1.0.

  - Rebase pidgin-crash-missing-gst-registry.patch.

  + add pidgin-crash-missing-gst-registry.patch according to
    the GST doc, 'gst_init' should be called before any
    other calls."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=853038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=874606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902495"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/13");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"finch-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"finch-debuginfo-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"finch-devel-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpurple-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpurple-branding-openSUSE-13.2-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpurple-branding-upstream-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpurple-debuginfo-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpurple-devel-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpurple-lang-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpurple-meanwhile-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpurple-meanwhile-debuginfo-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpurple-tcl-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpurple-tcl-debuginfo-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pidgin-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pidgin-debuginfo-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pidgin-debugsource-2.10.10-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pidgin-devel-2.10.10-5.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpurple-branding-openSUSE / finch / finch-debuginfo / finch-devel / etc");
}
