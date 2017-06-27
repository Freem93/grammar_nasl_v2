#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-640.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79106);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/13 14:27:26 $");

  script_cve_id("CVE-2014-3566");

  script_name(english:"openSUSE Security Update : claws-mail (openSUSE-SU-2014:1384-1) (POODLE)");
  script_summary(english:"Check for the openSUSE-2014-640 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Claws Mail was updated to version 3.11.0.

Changes :

  + SSLv3 server connections are now disabled by default, in
    response to the POODLE vulnerability (CVE-2014-3566).

  + Several PGP/Core plugin improvements :

  - Indicate when a key has been revoked or has expired when
    displaying signature status.

  - When displaying the full information, show the Validity,
    and the Owner Trust level. Also indicate expired and
    revoked keys, and revoked UIDs.

  - The 'Content-Disposition: attachment' flag in PGP/MIME
    signed messages has been removed. It was confusing for
    cetain MUAs.

  + A new version of the RSSyl plugin, completely redesigned
    and rewritten.

  + The results of TAB address completion in the Compose
    window have improved ordering.

  + Due to popular demand, use of the Up key in the message
    body in the Compose window stops at the top of the
    message body and does not continue up to the header
    fields. This reverts the behaviour introduced in version
    3.10.0.

  + In the Compose window, when navigating with the arrow
    keys, selecting, and thus modifying, the Account
    selector is now prevented.

  + In the Compose window, a mnemonic (s) has been added to
    the Subject line.

  + The Queue folder is highlighted if there are messages in
    its sub-folders and the tree is collapsed.

  + When sorting messages by 'thread date', clicking the
    'Date' column header will now toggle between
    ascending/descending and will not switch to 'date'
    sorting.

  + A new QuickSearch filter has been added that searches a
    header's content only.

  + A Reply-To field has been added to the main Template
    configuration.

  + The menubar can now be hidden, default hotkey: F12.

  + Fancy plugin: A user-controlled stylesheet can now be
    used.

  + Python plugin: Add flag attributes to MessageInfo
    object.

  + Python plugin: Make 'account' property of ComposeWindow
    read/write.

  + Libravatar plugin: a network timeout option has been
    added.

  + The tbird2claws.py script, for converting a Thunderbird
    mailbox to a Claws Mail mailbox, now handles
    sub-directory recursion.

  + Updated translations"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=903276"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected claws-mail packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/03");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/11");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"claws-mail-3.11.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"claws-mail-debuginfo-3.11.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"claws-mail-debugsource-3.11.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"claws-mail-devel-3.11.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"claws-mail-lang-3.11.0-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "claws-mail");
}
