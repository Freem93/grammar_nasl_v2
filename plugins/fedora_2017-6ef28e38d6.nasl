#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-6ef28e38d6.
#

include("compat.inc");

if (description)
{
  script_id(99697);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/27 13:33:46 $");

  script_cve_id("CVE-2017-2669");
  script_xref(name:"FEDORA", value:"2017-6ef28e38d6");

  script_name(english:"Fedora 25 : 1:dovecot (2017-6ef28e38d6)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  + quota: Add plugin { quota_max_mail_size } setting to
    limit the maximum individual mail size that can be
    saved.

  + imapc: Add imapc_features=delay-login. If set,
    connecting to the remote IMAP server isn't done until
    it's necessary.

  + imapc: Add imapc_connection_retry_count and
    imapc_connection_retry_interval settings.

  + imap, pop3, indexer-worker: Add (deinit) to process
    title before autoexpunging runs.

  + Added %{encrypt} and %{decrypt} variables

  + imap/pop3 proxy: Log proxy state in errors as
    human-readable string.

  + imap/pop3-login: All forward_* extra fields returned by
    passdb are sent to the next hop when proxying using
    ID/XCLIENT commands. On the receiving side these fields
    are imported and sent to auth process where they're
    accessible via %{passdb:forward_*}. This is done only if
    the sending IP address matches login_trusted_networks.

  + imap-login: If imap_id_retain=yes, send the IMAP ID
    string to auth process. %{client_id} expands to it in
    auth process. The ID string is also sent to the next hop
    when proxying.

  + passdb imap: Use ssl_client_ca_* settings for CA
    validation.

  - fts-tika: Fixed crash when parsing attachment without
    Content-Disposition header. Broken by 2.2.28.

  - trash plugin was broken in 2.2.28

  - auth: When passdb/userdb lookups were done via
    auth-workers, too much data was added to auth cache.
    This could have resulted in wrong replies when using
    multiple passdbs/userdbs.

  - auth: passdb { skip & mechanisms } were ignored for the
    first passdb

  - oauth2: Various fixes, including fixes to crashes

  - dsync: Large Sieve scripts (or other large metadata)
    weren't always synced.

  - Index rebuild (e.g. doveadm force-resync) set all mails
    as \Recent

  - imap-hibernate: %{userdb:*} wasn't expanded in
    mail_log_prefix

  - doveadm: Exit codes weren't preserved when proxying
    commands via doveadm-server. Almost all errors used exit
    code 75 (tempfail).

  - ACLs weren't applied to not-yet-existing autocreated
    mailboxes.

  - Fixed a potential crash when parsing a broken message
    header.

  - cassandra: Fallback consistency settings weren't working
    correctly.

  - doveadm director status <user>: 'Initial config' was
    always empty

  - imapc: Various reconnection fixes.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-6ef28e38d6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 1:dovecot package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"dovecot-2.2.29.1-1.fc25", epoch:"1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:dovecot");
}
