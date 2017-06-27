#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-6338.
#

include("compat.inc");

if (description)
{
  script_id(74048);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 22:40:31 $");

  script_cve_id("CVE-2014-3430");
  script_bugtraq_id(67306);
  script_xref(name:"FEDORA", value:"2014-6338");

  script_name(english:"Fedora 20 : dovecot-2.2.13-1.fc20 (2014-6338)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fixed a DoS attack against imap/pop3-login processes. If
    SSL/TLS handshake was started but wasn't finished, the
    login process attempted to eventually forcibly
    disconnect the client, but failed to do it correctly.
    This could have left the connections hanging arond for a
    long time. (Affected Dovecot v1.1+)

  - mdbox: Added mdbox_purge_preserve_alt setting to keep
    the file within alt storage during purge.

  - fts: Added support for parsing attachments via Apache
    Tika. Enable with: plugin { fts_tika =
    http://tikahost:9998/tika/ }

  - virtual plugin: Delay opening backend mailboxes until
    it's necessary. This requires mailbox_list_index=yes to
    work. (Currently IMAP IDLE command still causes all
    backend mailboxes to be opened.)

  - mail_never_cache_fields=* means now to disable all
    caching. This may be a useful optimization as
    doveadm/dsync parameter for some admin tasks which
    shouldn't really update the cache file.

  - IMAP: Return SPECIAL-USE flags always for LSUB command.

  - pop3 server was still crashing in v2.2.12 with some
    settings

  - maildir: Various fixes and improvements to handling
    compressed mails, especially when they have
    broken/missing S=sizes in filenames.

  - fts-lucene, fts-solr: Fixed crash on search when the
    index contained duplicate entries.

  - Many fixes and performance improvements to dsync and
    replication

  - director was somewhat broken when there were exactly two
    directors in the ring. It caused errors about 'weak
    users' getting stuck.

  - mail_attachment_dir: Attachments with the last
    base64-encoded line longer than the rest wasn't handled
    correctly.

  - IMAP: SEARCH/SORT PARTIAL was handled completely wrong
    in v2.2.11+

  - acl: Global ACL file handling was broken when multiple
    entries matched the mailbox name. (Only the first entry
    was used.)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tikahost:9998/tika/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1096402"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-May/133439.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6038854"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC20", reference:"dovecot-2.2.13-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot");
}
