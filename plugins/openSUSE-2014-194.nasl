#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-194.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75283);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-2178", "CVE-2013-7176", "CVE-2013-7177");

  script_name(english:"openSUSE Security Update : fail2ban (openSUSE-SU-2014:0348-1)");
  script_summary(english:"Check for the openSUSE-2014-194 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The fail2ban tool was updated to version 0.8.12 to fix various
security issues and also brings bugfixes and features.

Security issues fixed: A remote unauthenticated attacker may cause
arbitrary IP addresses to be blocked by Fail2ban causing legitimate
users to be blocked from accessing services protected by Fail2ban.
CVE-2013-7177 (cyrus-imap) and CVE-2013-7176 (postfix)

  - Use new flushlogs syntax after logrotate

  - Update to version 0.8.12

  - Log rotation can now occur with the command 'flushlogs'
    rather than reloading fail2ban or keeping the logtarget
    settings consistent in jail.conf/local and
    /etc/logrotate.d/fail2ban. (dep#697333, rh#891798).

  - Added ignorecommand option for allowing dynamic
    determination as to ignore and IP or not.

  - Remove indentation of name and loglevel while logging to
    SYSLOG to resolve syslog(-ng) parsing problems.
    (dep#730202). Log lines now also report '[PID]' after
    the name portion too.

  - Epoch dates can now be enclosed within []

  - New actions: badips, firewallcmd-ipset, ufw,
    blocklist_de

  - New filters: solid-pop3d, nsd, openwebmail, horde,
    freeswitch, squid, ejabberd, openwebmail, groupoffice

  - Filter improvements :

  - apache-noscript now includes php cgi scripts

  - exim-spam filter to match spamassassin log entry for
    option SAdevnull.

  - Added to sshd filter expression for 'Received disconnect
    from : 3: Auth fail'

  - Improved ACL-handling for Asterisk

  - Added improper command pipelining to postfix filter.

  - General fixes :

  - Added lots of jail.conf entries for missing filters that
    creaped in over the last year.

  - synchat changed to use push method which verifies
    whether all data was send. This ensures that all data is
    sent before closing the connection.

  - Fixed python 2.4 compatibility (as sub-second in date
    patterns weren't 2.4 compatible)

  - Complain/email actions fixed to only include relevant
    IPs to reporting

  - Filter fixes :

  - Added HTTP referrer bit of the apache access log to the
    apache filters.

  - Apache 2.4 perfork regexes fixed

  - Kernel syslog expression can have leading spaces

  - allow for ',milliseconds' in the custom date format of
    proftpd.log

  - recidive jail to block all protocols

  - smtps not a IANA standard so may be missing from
    /etc/services. Due to (still) common use 465 has been
    used as the explicit port number

  - Filter dovecot reordered session and TLS items in regex
    with wider scope for session characters

  - Ugly Fixes (Potentially incompatible changes) :

  - Unfortunately at the end of last release when the action
    firewall-cmd-direct-new was added it was too long and
    had a broken action check. The action was renamed to
    firewallcmd-new to fit within jail name name length.
    (gh#fail2ban/fail2ban#395).

  - Last release added mysqld-syslog-iptables as a jail
    configuration. This jailname was too long and it has
    been renamed to mysqld-syslog.

  - Fixed formating of github references in changelog

  - reformatted spec-file



  - Update to version 0.8.11

  - In light of CVE-2013-2178 that triggered our last
    release we have put a significant effort into tightening
    all of the regexs of our filters to avoid another
    similar vulnerability. We haven't examined all of these
    for a potential DoS scenario however it is possible that
    another DoS vulnerability exists that is fixed by this
    release. A large number of filters have been updated to
    include more failure regexs supporting previously
    unbanned failures and support newer application versions
    too. We have test cases for most of these now however if
    you have other examples that demonstrate that a filter
    is insufficient we welcome your feedback. During the
    tightening of the regexs to avoid DoS vulnerabilities
    there is the possibility that we have inadvertently,
    despite our best intentions, incorrectly allowed a
    failure to continue.

    Addresses a possible DoS. Closes
    gh#fail2ban/fail2ban#248, bnc#824710 within [Init].
    Closes gh#fail2ban/fail2ban#232

  - Updates to asterisk filter. Closes
    gh#fail2ban/fail2ban#227, gh#fail2ban/fail2ban#230.

  - Updates to asterisk to include AUTH_UNKNOWN_DOMAIN.
    Closes gh#fail2ban/fail2ban#244. on Fedora. Closes
    gh#fail2ban/fail2ban#112. Thanks to Camusensei for the
    bug report. insight. Closes gh#fail2ban/fail2ban#103.

  - [f2156604] pyinotify -- monitor IN_MOVED_TO events.
    Closes gh#fail2ban/fail2ban#184. Thanks to Jon Foster
    for report and troubleshooting. Orion Poplawski

  - [39667ff6] Avoid leaking file descriptors. Closes
    gh#fail2ban/fail2ban#167. Closes
    gh#fail2ban/fail2ban#147, gh#fail2ban/fail2ban#148.

  - [b6a68f51] Fix delaction on server side. Closes
    gh#fail2ban/fail2ban#124. the fail2ban-client. Closes
    gh#fail2ban/fail2ban#134. gh#fail2ban/fail2ban#70.
    Thanks to iGeorgeX for the idea.

  - [96eb8986] ' and ' should also be escaped in action tags
    Closes gh#fail2ban/fail2ban#109 beilber for the idea.
    Closes gh#fail2ban/fail2ban#114. fail2ban is running.
    Closes gh#fail2ban/fail2ban#166.

  - [29d0df5] Add mysqld filter. Closes
    gh#fail2ban/fail2ban#152.

  - [bba3fd8] Add Sogo filter. Closes
    gh#fail2ban/fail2ban#117.

  - [be06b1b] Add action for iptables-ipsets. Closes
    gh#fail2ban/fail2ban#102.

  - [f336d9f] Add filter for webmin. Closes
    gh#fail2ban/fail2ban#99. consistently. Closes
    gh#fail2ban/fail2ban#172.

  - [b36835f] Add get cinfo to fail2ban-client. Closes
    gh#fail2ban/fail2ban#124. Closes
    gh#fail2ban/fail2ban#142. Closes
    gh#fail2ban/fail2ban#126. Bug report by Michael
    Heuberger.

  - [3aeb1a9] Add jail.conf manual page. Closes
    gh#fail2ban/fail2ban#143. banning due to misconfigured
    DNS. Close gh#fail2ban/fail2ban#64

  - [0935566,5becaf8] Various python 2.4 and 2.5
    compatibility fixes. Close gh#fail2ban/fail2ban#83 in
    the console. Close gh#fail2ban/fail2ban#91 the log file
    to take 'banip' or 'unbanip' in effect. Close
    gh#fail2ban/fail2ban#81, gh#fail2ban/fail2ban#86

  - [f52ba99] downgraded 'already banned' from WARN to INFO
    level. Closes gh#fail2ban/fail2ban#79 for this
    gh#fail2ban/fail2ban#87) message stays non-unicode.
    Close gh#fail2ban/fail2ban#32 friend to developers stuck
    with Windows (Closes gh#fail2ban/fail2ban#66) repeated
    offenders. Close gh#fail2ban/fail2ban#19 Close
    gh#fail2ban/fail2ban#47 (Closes: #669063)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=861503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=861504"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fail2ban package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fail2ban");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/28");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"fail2ban-0.8.12-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"fail2ban-0.8.12-2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fail2ban");
}
