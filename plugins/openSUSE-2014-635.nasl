#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-635.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79101);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/17 12:13:04 $");

  script_cve_id("CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3697", "CVE-2014-3698");

  script_name(english:"openSUSE Security Update : pidgin (openSUSE-SU-2014:1376-1)");
  script_summary(english:"Check for the openSUSE-2014-635 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following issues were fixed in this update :

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

  + Yahoo: Fix login when using the GnuTLS library for TLS
    connections (im#16172, boo#874606)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00023.html"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-otr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-otr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-otr-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/11");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"finch-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"finch-debuginfo-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"finch-devel-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-branding-openSUSE-12.2-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-branding-upstream-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-debuginfo-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-devel-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-lang-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-meanwhile-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-meanwhile-debuginfo-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-tcl-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-tcl-debuginfo-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-debuginfo-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-debugsource-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-devel-2.10.10-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-otr-4.0.0-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-otr-debuginfo-4.0.0-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-otr-debugsource-4.0.0-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"finch-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"finch-debuginfo-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"finch-devel-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-branding-openSUSE-13.1-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-branding-upstream-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-debuginfo-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-devel-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-lang-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-meanwhile-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-meanwhile-debuginfo-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-tcl-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-tcl-debuginfo-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-debuginfo-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-debugsource-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-devel-2.10.10-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-otr-4.0.0-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-otr-debuginfo-4.0.0-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-otr-debugsource-4.0.0-4.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpurple-branding-openSUSE / pidgin-otr / pidgin-otr-debuginfo / etc");
}
