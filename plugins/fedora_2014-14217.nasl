#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-14217.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79096);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_xref(name:"FEDORA", value:"2014-14217");

  script_name(english:"Fedora 21 : claws-mail-3.11.1-2.fc21 / claws-mail-plugins-3.11.1-1.fc21 / libetpan-1.6-1.fc21 (2014-14217) (POODLE)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - SSLv3 server connections are now disabled by default, in
    response to the POODLE vulnerability, see
    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-
    3566.

  - Several PGP/Core plugin improvements

  - A new version of the RSSyl plugin, completely redesigned
    and rewritten.

  - The results of TAB address completion in the Compose
    window have improved ordering.

  - Due to popular demand, use of the Up key in the message
    body in the Compose window stops at the top of the
    message body and does not continue up to the header
    fields. This reverts the behaviour introduced in version
    3.10.0.

  - In the Compose window, when navigating with the arrow
    keys, selecting, and thus modifying, the Account
    selector is now prevented.

  - In the Compose window, a mnemonic (s) has been added to
    the Subject line.

  - The Queue folder is highlighted if there are messages in
    its sub-folders and the tree is collapsed.

  - When sorting messages by 'thread date', clicking the
    'Date' column header will now toggle between
    ascending/descending and will not switch to 'date'
    sorting.

  - A new QuickSearch filter has been added that searches a
    header's content only. H S : messages which contain S in
    the value of any header.

  - A Reply-To field has been added to the main Template
    configuration.

  - The menubar can now be hidden, default hotkey: F12.

  - Fancy plugin: A user-controlled stylesheet can now be
    used.

  - Python plugin: Add flag attributes to MessageInfo
    object.

  - Python plugin: Make 'account' property of ComposeWindow
    read/write.

  - Libravatar plugin: a network timeout option has been
    added.

  - Use 'gnutls_priority' hidden account preference for POP3
    and STARTTLS connections, in addition to SMTP.

  - RSSyl plugin: Enable use of .netrc to store network
    credentials.

  - The tbird2claws.py script, for converting a Thunderbird
    mailbox to a Claws Mail mailbox, now handles
    sub-directory recursion.

  - Updated translations

  - Various Bugfixes New in 3.10.1 :

  - Add an account preference to allow automatically
    accepting unknown and changed SSL certificates, if
    they're valid (that is, if the root CA is trusted by the
    distro).

  - RFE 3196, 'When changing quicksearch Search Type, set
    focus to search input box'

  - PGP/Core plugin: Generate 2048 bit RSA keys.

  - Major code cleanup.

  - Extended claws-mail.desktop with Compose and Receive
    actions.

  - Updated Bulgarian, Brazilian Portuguese, Czech, Dutch,
    Esperanto, Finnish, French, German,Hebrew, Hungarian,
    Indonesian, Lithuanian, Slovak, Spanish, and Swedish
    translations.

  - Bug fixes

New in 3.10.0 :

  - Complete SSL certificate chains are now saved, and if
    built with Libetpan 1.4.1, the IMAP SSL connection's
    certificate chain is made available. Both of these allow
    correct certificate verification instead of a bogus 'No
    certificate issuer found' status.

  - Auto-configuration of account email servers, based on
    SRV records, is now possible. (GLib >= 2.22 is
    required.)

  - Added a preference to avoid automatically drafting
    emails that are to be sent encrypted,
    (Configuration/Preferences/Compose/Writing).

  - Messages saved as Drafts are now saved as New,
    highlighting the Drafts folder, in order to draw the
    attention to unfinished mails there.

  - It is now possible to add a 'Replace signature' button
    to the Compose window toolbar.

  - Quotation wrapping and undo/redo in the Compose window
    has been improved.

  - 'Reply to all' now excludes your own address.

  - The 'Generate X-Mailer header' option has been renamed
    'Add user agent header' and applies to both X-Mailer and
    X-Newsreader headers.

  - Added hidden preferences, 'address_search_wildcard' and
    'folder_search_wildcard', to choose between matching
    from start of the folder name/address or any part of the
    name. (Activating these options restores the previous
    behaviour.)

  - Added hidden preference 'enable_avatars' to control the
    internal capture/render process, and which allows
    disabling it by external plugins for example.

  - 'Check for new folders' now only updates the folder
    list, not updating the contents of folders. If needed,
    it can be followed by 'Check for new messages'

  - When using Redirect, the redirecting account's address
    is used in the SMTP MAIL FROM instead of the original
    sender's address.

  - NEW: Libravatar plugin, which displays avatars from
    https://www.libravatar.org/

  - Added support for an arbitrary number and sources of
    'avatars' and images for email senders, and migrated
    Face and X-Face headers.

  - Avatars are now included when printing mails.

  - The GPG keyring can now be used as the source for
    address auto-completion.

  - The vCalendar and RSSyl plugins now have an option to
    disable SSL certificate verification (and check them by
    default).

  - The ClamAV plugin now pops up an error message only once
    instead of repeatedly

  - Updated the man page and the manual.

  - Updated Brazilian Portuguese, British English, Czech,
    Dutch, Finnish, French, Hebrew, Hungarian, Indonesian,
    Lithuanian, Slovak, Spanish, and Swedish translations.

  - Added Esperanto translation.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1010993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1011098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1035851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1036346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1063035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1070480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1071327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1076387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1078996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1079509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1079620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1081224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1085382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1090300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1096041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1096895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1110255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1153970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=569478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=601982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=977924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=982533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=990650"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/143162.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97a8a38f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/143163.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e11dcb5d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/143164.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a72459de"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.libravatar.org/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected claws-mail, claws-mail-plugins and / or libetpan
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:claws-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:claws-mail-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libetpan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/03");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"claws-mail-3.11.1-2.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"claws-mail-plugins-3.11.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"libetpan-1.6-1.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "claws-mail / claws-mail-plugins / libetpan");
}
