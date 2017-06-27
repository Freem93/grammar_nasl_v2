#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0353-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83687);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2015-0240");
  script_bugtraq_id(72711);
  script_osvdb_id(118637);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : samba (SUSE-SU-2015:0353-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"samba was updated to fix one security issue.

This security issue was fixed :

  - CVE-2015-0240: Don't call talloc_free on an
    uninitialized pointer (bnc#917376).

These non-security issues were fixed :

  - Fix vfs_snapper DBus string handling (bso#11055,
    bnc#913238).

  - Fix libsmbclient DFS referral handling.

  - Reuse connections derived from DFS referrals
    (bso#10123).

  - Set domain/workgroup based on authentication callback
    value (bso#11059).

  - pam_winbind: Fix warn_pwd_expire implementation
    (bso#9056).

  - nsswitch: Fix soname of linux nss_*.so.2 modules
    (bso#9299).

  - Fix profiles tool (bso#9629).

  - s3-lib: Do not require a password with --use-ccache
    (bso#10279).

  - s4:dsdb/rootdse: Expand extended dn values with the
    AS_SYSTEM control (bso#10949).

  - s4-rpc: dnsserver: Fix enumeration of IPv4 and IPv6
    addresses (bso#10952).

  - s3:smb2_server: Allow reauthentication without signing
    (bso#10958).

  - s3-smbclient: Return success if we listed the shares
    (bso#10960).

  - s3-smbstatus: Fix exit code of profile output
    (bso#10961).

  - libcli: SMB2: Pure SMB2-only negprot fix to make us
    behave as a Windows client does (bso#10966).

  - s3: smbd/modules: Fix *allocate* calls to follow POSIX
    error return convention (bso#10982).

  - Fix 'domain join' by adding 'drsuapi.DsBindInfoFallBack'
    attribute 'supported_extensions' (bso#11006).

  - idl:drsuapi: Manage all possible lengths of
    drsuapi_DsBindInfo (bso#11006).

  - winbind: Retry LogonControl RPC in ping-dc after session
    expiration (bso#11034).

  - yast2-samba-client should be able to specify osName and
    osVer on AD domain join (bnc#873922).

  - Lookup FSRVP share snums at runtime rather than storing
    them persistently (bnc#908627).

  - Specify soft dependency for network-online.target in
    Winbind systemd service file (bnc#889175).

  - Fix spoolss error response marshalling; (bso#10984).

  - pidl/wscript: Remove --with-perl-* options; revert
    buildtools/wafadmin/ Tools/perl.py back to upstream
    state (bso#10472).

  - s4-dns: Add support for BIND 9.10 (bso#10620).

  - nmbd fails to accept '--piddir' option; (bso#10711).

  - S3: source3/smbd/process.c::srv_send_smb() returns true
    on the error path (bso#10880).

  - vfs_glusterfs: Remove 'integer fd' code and store the
    glfs pointers (bso#10889).

  - s3-nmbd: Fix netbios name truncation (bso#10896).

  - spoolss: Fix handling of bad EnumJobs levels
    (bso#10898).

  - spoolss: Fix jobid in level 3 EnumJobs response;
    (bso#10905).

  - s3: nmbd: Ensure NetBIOS names are only 15 characters
    stored; (bso#10920).

  - s3:smbd: Fix file corruption using 'write cache size !=
    0'; (bso#10921).

  - pdb_tdb: Fix a TALLOC/SAFE_FREE mixup; (bso#10932).

  - s3-keytab: Fix keytab array NULL termination;
    (bso#10933).

  - Cleanup add_string_to_array and usage; (bso#10942).

  - Remove and cleanup shares and registry state associated
    with externally deleted snaphots exposed as shadow
    copies; (bnc#876312).

  - Use the upstream tar ball, as signature verification is
    now able to handle compressed archives.

  - Fix leak when closing file descriptor returned from
    dirfd; (bso#10918).

  - Fix spoolss EnumJobs and GetJob responses; (bso#10905);
    (bnc#898031).

  - Fix handling of bad EnumJobs levels; (bso#10898).

  - Remove dependency on gpg-offline as signature checking
    is implemented in the source validator.

  - s3-libnet: Add libnet_join_get_machine_spns();
    (bso#9984).

  - s3-libnet: Make sure we do not overwrite precreated
    SPNs; (bso#9984).

  - s3-libads: Add all machine account principals to the
    keytab; (bso#9985).

  - s3: winbindd: Old NT Domain code sets struct
    winbind_domain->alt_name to be NULL. Ensure this is safe
    with modern AD-DCs; (bso#10717).

  - Fix unstrcpy; (bso#10735).

  - pthreadpool: Slightly serialize jobs; (bso#10779).

  - s3: smbd: streams - Ensure share mode validation ignores
    internal opens (op_mid == 0); (bso#10797).

  - s3: smbd:open_file: Open logic fix; Use a more natural
    check; (bso#10809).

  - vfs_media_harmony: Fix a crash bug; (bso#10813).

  - docs: Mention incompatibility between kernel oplocks and
    streams_xattr; (bso#10814).

  - nmbd: Send waiting status to systemd; (bso#10816).

  - libcli: Fix a segfault calling smbXcli_req_set_pending()
    on NULL; (bso#10817).

  - nsswitch: Skip groups we were not able to map;
    (bso#10824).

  - s3-winbindd: Use correct realm for trusted domains in
    idmap child; (bso#10826).

  - s3: nmbd: Ensure the main nmbd process doesn't create
    zombies; (bso#10830).

  - s3: lib: Signal handling - ensure smbrun and change
    password code save and restore existing SIGCHLD
    handlers; (bso#10831).

  - idmap_rfc2307: Fix a crash after connection problem to
    DC; (bso#10837).

  - s3-winbindd: Do not use domain SID from LookupSids for
    Sids2UnixIDs call; (bso#10838).

  - s3: smb2cli: Query info return length check was
    reversed; (bso#10848).

  - registry: Don't leave dangling transactions;
    (bso#10860).

  - Prune idle or hung connections older than 'winbind
    request timeout'; (bso#3204); (bnc#872912).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0240.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/872912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/873922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/876312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/889175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/898031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/913238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917376"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150353-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3122dc9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-91=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-91=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-91=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgensec0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgensec0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libregistry0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libregistry0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-raw0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-raw0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc-binding0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc-binding0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgensec0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgensec0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-krb5pac0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-krb5pac0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-nbt0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-nbt0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-standard0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-standard0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libnetapi0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libnetapi0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpdb0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpdb0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libregistry0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libregistry0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-credentials0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-credentials0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-hostconfig0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-hostconfig0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-util0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-util0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamdb0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamdb0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient-raw0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient-raw0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbconf0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbconf0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbldap0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbldap0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtevent-util0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtevent-util0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libwbclient0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libwbclient0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-client-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-client-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-debugsource-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-libs-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-libs-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-winbind-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-winbind-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc-binding0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc-binding0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgensec0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgensec0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-krb5pac0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-krb5pac0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-nbt0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-nbt0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-standard0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-standard0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libnetapi0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libnetapi0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpdb0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpdb0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-credentials0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-credentials0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-hostconfig0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-hostconfig0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-util0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-util0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamdb0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamdb0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient-raw0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient-raw0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbconf0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbconf0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbldap0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbldap0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtevent-util0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtevent-util0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libwbclient0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libwbclient0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-client-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-client-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-libs-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-libs-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-winbind-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-winbind-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc-binding0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgensec0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgensec0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgensec0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgensec0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-krb5pac0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-nbt0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-standard0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-standard0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-standard0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libnetapi0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libnetapi0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libnetapi0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpdb0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpdb0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpdb0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpdb0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libregistry0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libregistry0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-credentials0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-hostconfig0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-util0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-util0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-util0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamdb0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamdb0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamdb0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient-raw0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient-raw0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbconf0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbconf0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbconf0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbldap0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbldap0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbldap0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtevent-util0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtevent-util0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtevent-util0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwbclient0-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwbclient0-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwbclient0-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-client-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-client-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-client-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-debugsource-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-libs-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-libs-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-libs-debuginfo-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-winbind-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-winbind-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.1.12-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-winbind-debuginfo-4.1.12-16.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
