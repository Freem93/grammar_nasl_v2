#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-655.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75124);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2013-4852");
  script_osvdb_id(95970);

  script_name(english:"openSUSE Security Update : putty (openSUSE-SU-2013:1355-1)");
  script_summary(english:"Check for the openSUSE-2013-655 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Putty was updated to 0.63, bringing features, bug and security fixes.

Changes :

  - Add 0001-Revert-the-default-for-font-bolding-style.patch
    (upstream patch fixing a cosmetic change introduced in
    0.63)

  - Add Conflict tag against pssh package (Parallel SSH) due
    to conflicting files in /usr/bin

  - Do signature verification

  - update to 0.63

  - Security fix: prevent a nefarious SSH server or network
    attacker from crashing PuTTY at startup in three
    different ways by presenting a maliciously constructed
    public key and signature. [bnc#833567] CVE-2013-4852

  - Security fix: PuTTY no longer retains the private half
    of users' keys in memory by mistake after authenticating
    with them.

  - Revamped the internal configuration storage system to
    remove all fixed arbitrary limits on string lengths. In
    particular, there should now no longer be an
    unreasonably small limit on the number of port
    forwardings PuTTY can store.

  - Forwarded TCP connections which close one direction
    before the other should now be reliably supported, with
    EOF propagated independently in the two directions. This
    also fixes some instances of forwarding data corruption
    (if the corruption consisted of losing data from the
    very end of the connection) and some instances of PuTTY
    failing to close when the session is over (because it
    wrongly thought a forwarding channel was still active
    when it was not).

  - The terminal emulation now supports xterm's bracketed
    paste mode (allowing aware applications to tell the
    difference between typed and pasted text, so that e.g.
    editors need not apply inappropriate auto-indent).

  - You can now choose to display bold text by both
    brightening the foreground colour and changing the font,
    not just one or the other.

  - PuTTYgen will now never generate a 2047-bit key when
    asked for 2048 (or more generally n&minus;1 bits when
    asked for n).

  - Some updates to default settings: PuTTYgen now generates
    2048-bit keys by default (rather than 1024), and PuTTY
    defaults to UTF-8 encoding and 2000 lines of scrollback
    (rather than ISO 8859-1 and 200).

  - Unix: PSCP and PSFTP now preserve the Unix file
    permissions, on copies in both directions.

  - Unix: dead keys and compose-character sequences are now
    supported.

  - Unix: PuTTY and pterm now permit font fallback (where
    glyphs not present in your selected font are
    automatically filled in from other fonts on the system)
    even if you are using a server-side X11 font rather than
    a Pango client-side one.

  - Bug fixes too numerous to list, mostly resulting from
    running the code through Coverity Scan which spotted an
    assortment of memory and resource leaks, logic errors,
    and crashes in various circumstances. 

  - packaging changes :

  - run make from base directory

  - run tests

  - remove putty-01-werror.diff (currently not needed)

  - remove putty-02-remove-gtk1.diff,
    putty-05-glib-deprecated.diff,
    putty-06-gtk2-indivhdr.diff (no longer needed)

  - refresh putty-03-config.diff

  - remove autoconf calls and requirements

  - package HTML documentation

  - package LICENCE file"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833567"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected putty packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:putty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:putty-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:putty-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.3", reference:"putty-0.63-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"putty-debuginfo-0.63-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"putty-debugsource-0.63-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "putty / putty-debuginfo / putty-debugsource");
}
