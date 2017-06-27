#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-13860.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56486);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/11 13:24:20 $");

  script_cve_id("CVE-2011-3208");
  script_bugtraq_id(49534);
  script_xref(name:"FEDORA", value:"2011-13860");

  script_name(english:"Fedora 15 : cyrus-imapd-2.4.12-1.fc15 (2011-13860)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - security fix :

    - fixes incomplete authentication checks in nntpd
      (Secunia SA46093)

    - other fixed bugs :

    - delayed delete can fail because of invalid names

    - cyradm cannot wildcard delete ACLs from a mailbox

    - Wrong ENABLE result (doubled names)

    - mbpath output changed from 2.3 to 2.4 for remote
      mailboxes

    - xfer fails on unlimited quota (-1)

CVE-2011-3208 cyrus-imapd: nntpd buffer overflow in split_wildmats()

Bugs Fixed :

3495 P1 enhancement 2.4.10 Cyrus IMAP Improved duplicate suppression
3498 P1 bug 2.4.10 Cyrus IMAP quota command deletes users quota files
2772 P2 bug 2.4.x (next) Cyrus IMAP cmd_thread cores with bogus ids in
references header 3300 P3 bug 2.4.2 Cyrus IMAP SOL_TCP is not defined
on NetBSD 3439 P3 bug 2.3.16 Cyrus IMAP formatting issue on logging
(or memory corruption ?) 3454 P3 bug 2.4.8 Cyrus IMAP ID with unquoted
id_param_list keys not accepted 3463 P3 bug 2.4.x (next) Cyrus IMAP
Certain mails will crash imapd if using server side threading 3489 P3
bug 2.4.10 Cyrus IMAP 2.4.10 and quota problem 3491 P3 enhancement
2.4.10 Cyrus IMAP UNAUTHENTICATE and NOOP in timsieved 3492 P3 bug
2.4.10 Cyrus IMAP Add response codes to timsieved 3497 P3 bug 2.4.10
Cyrus IMAP In master/master.c:add_service the variable 'cmd' is set to
NULL before syslogging 3503 P3 bug 2.4.10 Cyrus IMAP DragonFly BSD
also require PIC objects for perl 3505 P3 bug 2.4.x (next) Cyrus IMAP
sync_reset is broken 3506 P3 bug 2.4.x (next) Cyrus IMAP dlist.c uses
synchronizing IMAP LITERALS without backchannel. 3507 P3 bug 2.4.x
(next) Cyrus IMAP Replication reconciliation fails in
default/immediate expunge mode 3526 P3 bug 2.4.10 Cyrus IMAP AFS
ptloader reinitialization uses local cell instead of afspts_mycell
config option 3532 P3 enhancement 2.5.x (next) Cyrus IMAP Fix file
descriptor cleanup 3279 P5 bug 2.4.2 Cyrus IMAP sync_client crashes
with empty mech_list before TLS starts 3451 P5 enhancement 2.4.8 Cyrus
IMAP config2header assume CC has no spaces

  - rebuild to match db library update

    - do not conflict with db4-utils

    - rebuild to match db library update CVE-2011-3208
      cyrus-imapd: nntpd buffer overflow in split_wildmats()

Bugs Fixed :

3495 P1 enhancement 2.4.10 Cyrus IMAP Improved duplicate suppression
3498 P1 bug 2.4.10 Cyrus IMAP quota command deletes users quota files
2772 P2 bug 2.4.x (next) Cyrus IMAP cmd_thread cores with bogus ids in
references header 3300 P3 bug 2.4.2 Cyrus IMAP SOL_TCP is not defined
on NetBSD 3439 P3 bug 2.3.16 Cyrus IMAP formatting issue on logging
(or memory corruption ?) 3454 P3 bug 2.4.8 Cyrus IMAP ID with unquoted
id_param_list keys not accepted 3463 P3 bug 2.4.x (next) Cyrus IMAP
Certain mails will crash imapd if using server side threading 3489 P3
bug 2.4.10 Cyrus IMAP 2.4.10 and quota problem 3491 P3 enhancement
2.4.10 Cyrus IMAP UNAUTHENTICATE and NOOP in timsieved 3492 P3 bug
2.4.10 Cyrus IMAP Add response codes to timsieved 3497 P3 bug 2.4.10
Cyrus IMAP In master/master.c:add_service the variable 'cmd' is set to
NULL before syslogging 3503 P3 bug 2.4.10 Cyrus IMAP DragonFly BSD
also require PIC objects for perl 3505 P3 bug 2.4.x (next) Cyrus IMAP
sync_reset is broken 3506 P3 bug 2.4.x (next) Cyrus IMAP dlist.c uses
synchronizing IMAP LITERALS without backchannel. 3507 P3 bug 2.4.x
(next) Cyrus IMAP Replication reconciliation fails in
default/immediate expunge mode 3526 P3 bug 2.4.10 Cyrus IMAP AFS
ptloader reinitialization uses local cell instead of afspts_mycell
config option 3532 P3 enhancement 2.5.x (next) Cyrus IMAP Fix file
descriptor cleanup 3279 P5 bug 2.4.2 Cyrus IMAP sync_client crashes
with empty mech_list before TLS starts 3451 P5 enhancement 2.4.8 Cyrus
IMAP config2header assume CC has no spaces

  - rebuild to match db library update

    - do not conflict with db4-utils

    - rebuild to match db library update

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=729767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=736838"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/068042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51e80815"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-imapd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"cyrus-imapd-2.4.12-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-imapd");
}
