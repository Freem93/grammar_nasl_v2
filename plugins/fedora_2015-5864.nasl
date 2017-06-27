#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-5864.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(83090);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 23:14:51 $");

  script_cve_id("CVE-2014-9465");
  script_xref(name:"FEDORA", value:"2015-5864");

  script_name(english:"Fedora 20 : zarafa-7.1.12-1.fc20 (2015-5864)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Zarafa Collaboration Platform 7.1.12 final [48726]
==================================================

  - ZCP-10149: Include Documentation hint for usage of NFS
    and -o nolock option

    - ZCP-10233: Zarafa-mr-accept script complains in
      certain cases about php timezone functions

    - ZCP-10578: missing prerequisites for the reverse proxy
      in the administrator manual

    - ZCP-10639: Incorrect message when trying to add an
      archive

    - ZCP-10919: a remote admin in multi tenant mode cannot
      resolve users

    - ZCP-11061: Bandwidth requirement documentation

    - ZCP-11413: Monitor complains on unused config options.

    - ZCP-11418: Compat features do not work with outlook
      2010 and windows 8

    - ZCP-11468: Document for a user who wants to use
      webapp, but is experiencing problems by using an
      unsupported browser, an easier area to locate the list
      of supported browsers

    - ZCP-11664: Remove 'you' wording from the WebApp User
      Manual

    - ZCP-11713: Japanese e-mail breaks the body text

    - ZCP-11744: zarafa-restore error in documentation

    - ZCP-11786: zarafa-ws is trying to put files in
      /usr/share/doc/zarafa

    - ZCP-11869: Documentation is not clear about
      Multitenant Public Folder attribute

    - ZCP-11929: differences between 'Managing tenant
      (company) spaces' and zarafa-admin

    - ZCP-11931: Outlook Client: synchronisation of an
      offline profile makes zarafa-server unresponsive

    - ZCP-11937: Setting out of office for the first time
      sets language to Catalan

    - ZCP-11949: Update documentation to stress that one
      server must have one database.

    - ZCP-12081: AB Provider UID is defined multiple times
      and may cause the server to read invalid memory

    - ZCP-12110: Segfault zarafa-server 7.1.8 R1

    - ZCP-12257: include location of the ads plugin in the
      manual

    - ZCP-12371: Add additional LDAP logging when using
      extended log level

    - ZCP-12409: zarafa-search crashes with ssl

    - ZCP-12424: Dagent in LMTP mode violates RFC5321

    - ZCP-12461: ECDatabaseMySQL defined twice

    - ZCP-12488: storing attachments in files on disk is not
      optimal implemented

    - ZCP-12491: Last date of a serial MR is ignored

    - ZCP-12492: Private mails sent from Exchange are not
      marked private.

    - ZCP-12501: Component documentation

    - ZCP-12534: Sending a mail to a group: The receivers do
      not see the group correctly.

    - ZCP-12549: remove mail subject from spooler.log

    - ZCP-12550: Zarafa-hidden does not work for cached
      outlook in ZCP 7.1.10

    - ZCP-12566: gsoap code gets our license attached in
      community distribution of zcp

    - ZCP-12568: ldap_uri slows down webapp and server after
      switching the LDAP-Server

    - ZCP-12574: meeting request copy to delegate - german
      umlauts broken

    - ZCP-12592: Update unsecure swfupload.swf

    - ZCP-12596: senddocument.php allows unauthorized upload
      of files

    - ZCP-12597: OL2013 15.0.4641.1001 shows private
      appointments

    - ZCP-12600: Sync seems to fail for larger objects

    - ZCP-12608: Compatibility package does not install
      correctly with OEM version of Outlook 2013 in every
      case

    - ZCP-12611: Cannot move appointment to different
      calendar

    - ZCP-12618: Move temporary patch definitions file to
      systemwide central location

    - ZCP-12629: zarafa-server binary does not check for
      existence of sockets and pids when started manually

    - ZCP-12657: Optimization of dagent incoming e-mail
      processing

    - ZCP-12660: Change runlevel of zarafa-licensed to start
      before zarafa-server

    - ZCP-12671: Add new OL2013 version 15.0.4659.1000
      client to compatibility component

    - ZCP-12676: IMAP Failed to read line: Interrupted
      system call

    - ZCP-12692: Stores should not be orphaned when
      user_safe_mode is active, even if they are back when
      correcting backend

    - ZCP-12696: SMTP RFC store violation

    - ZCP-12698: compile fail with recent g++ (4.9)

    - ZCP-12716: mails send with x-mailer 'CDO for windows
      2000' loses attachments.

    - ZCP-12720: SMTP RFC store violation

    - ZCP-12754: Document that its a bad idea to switch the
      connection type inside a profile

    - ZCP-12755: Add new OL2013 version 15.0.4667.1000
      client to compatibility component

    - ZCP-12762: remove userquota_soft_template &
      userquota_hard_template from documentation

    - ZCP-12766: zarafa-mailbox-permissions doesn't remove
      rules for --remove-all-permissions

    - ZCP-12788: Updating the name of a non-active user will
      change it to a active user

    - ZCP-12790: Message with attachments converted from
      uuencoded to attachments with uudecode.py

    - ZCP-12791: zarafa-server crashing due to ldap.cfg
      error

    - ZCP-12801: Attachments aren't written into the
      database

    - ZCP-12824: zarafa server still logs indexer instead of
      search.

    - ZCP-12845: storing attachments in files on disk is not
      optimal implemented

    - ZCP-12847: Change changelog author for debian/rhel
      packages

    - ZCP-12850: ECDatabaseMySQL defined twice

    - ZCP-12851: zarafa-gateway: NOOP returns with wrong
      return code

    - ZCP-12852: Reading an encypted or signed email will
      change the receive date of the email to server time

    - ZCP-12865: zarafa-gateway.cfg man page missing
      description of imap_max_fail_commands.

    - ZCP-12877: meeting request copy to delegate - german
      umlauts broken

    - ZCP-12889: Segfault zarafa-server 7.1.8 R1

    - ZCP-12892: Last date of a serial MR is ignored

    - ZCP-12898: zarafa-webaccess no login after update to
      7.1.10 on Ubuntu 10.04

    - ZCP-12901: mails send with x-mailer 'CDO for windows
      2000' loses attachments.

    - ZCP-12908: zarafa-server crashing due to ldap.cfg
      error

    - ZCP-12910: Monitor complains on unused config options.

    - ZCP-12914: Add comment in monitor.cfg for
      companyquota_warning_template

    - ZCP-12918: zarafa spooler queues mails forever if
      smtpd rejects the mail

    - ZCP-12920: As a user I want to be able to sort the
      global addresses book by Chinese character

    - ZCP-12921: Chinese character broken once received

    - ZCP-12922: remove userquota_soft_template &
      userquota_hard_template from documentation

    - ZCP-12923: Building from source fails when xmlto /
      libical / bison is missing

    - ZCP-12926: ECChannel::HrSelect doesn't handle EINTR as
      it should

    - ZCP-12930: zarafa-dagent segfault when deliver special
      mail

    - ZCP-12934: When reporting this traceback, please
      include Linux distribution name, system architecture
      and Zarafa version.

    - ZCP-12944: another chinese decode issue

    - ZCP-12945: Add new OL2013 version 15.0.4675.1003
      client to compatibility component

    - ZCP-12949: Update documentation for unsupported Oracle
      Packages

    - ZCP-12950: zarafa-dagent segfault when deliver special
      mail

    - ZCP-12968: ECChannel::HrSelect doesn't handle EINTR as
      it should

    - ZCP-12994: Disabling imap on a pop3 users breaks
      certain mail.

    - ZCP-12995: Example command given in 'Out of office
      management' is incomplete

    - ZCP-13015: add SSL settings for zcp 7.1

    - ZCP-13019: Update documentation for Debian language
      pack installation

    - ZCP-13020: zarafa-admin tool mismatch password gives
      wrong notification

    - ZCP-13024: allowed to create SYSTEM user

    - ZCP-13026: Add new OL2013 version 15.0.4693.1000
      client to compatibility component

    - ZCP-13030: Add new OL2010 version 14.0.7143.5000
      client to compatibility component

    - ZCP-13035: Rather use SSLCERT_FILE & SSLCERT_PASS when
      setting up SSO for WebApp/WebAccess

    - ZCP-13039: Add comment in monitor.cfg for
      companyquota_warning_template

    - ZCP-13046: Improve z-push documentation in admin
      manual

    - ZCP-13047: man page zarafa-admin --hook-store
      --copyto-public could use some extra information

    - ZCP-13055: Zarafa outlook client 7.1.11-48011 does not
      work well with zarafa auto updater

    - ZCP-13060: zarafa server still logs indexer instead of
      search.

    - ZCP-13061: Sync seems to fail for larger objects

    - ZCP-13062: Merge the compatibility package
      installation into the MSI typical install mode

    - ZCP-13082: patch: wrong charset in HTML

    - ZCP-13120: Add new OL2013 version 15.0.4701.1000
      client to compatibility component

    - ZCP-13123: Simplification of installation targets of
      compat package for manifest and c2r installations

    - ZCP-13143: Spooler.log gives wrong messages
      notifications

    - ZCP-13153: Outlook: answering on a message in 'send
      items' results in a message with empty Reply-To:
      header.

    - ZCP-13154: it would be helpful if phpmapi would
      produce a logfile

    - ZCP-13155: WebAccess /etc/zarafa/webaccess/config.php
      is not a symlink

    - ZCP-13158: Upgrade OpenSSL to 1.0.1m on Win32

    - ZCP-13176: zarafa-server binary does not check for
      existence of sockets and pids when started manually

    - ZCP-13177: patch: wrong charset in HTML

    - ZCP-13179: it would be helpful if phpmapi would
      produce a logfile

    - ZCP-13180: Spooler.log gives wrong messages
      notifications

    - ZCP-13187: Message with attachments converted from
      uuencoded to attachments with uudecode.py

    - ZCP-13190: Setting out of office for the first time
      sets language to Catalan

    - ZCP-13191: When reporting this traceback, please
      include Linux distribution name, system architecture
      and Zarafa version.

    - ZCP-13192: Incorrect message when trying to add an
      archive

    - ZCP-13194: remove mail subject from spooler.log

    - ZCP-6294: allowed to create SYSTEM user

    - ZCP-6443: zarafa-admin tool mismatch password gives
      wrong notification

    - ZCP-7085: Updating the name of a non-active user will
      change it to an active user

    - ZCP-7296: Extension on the administrator manual

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1139442"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/156228.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b9639da"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected zarafa package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:zarafa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"zarafa-7.1.12-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zarafa");
}
