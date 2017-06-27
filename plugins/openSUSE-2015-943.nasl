#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-943.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87621);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-3223", "CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299", "CVE-2015-5330", "CVE-2015-8467");

  script_name(english:"openSUSE Security Update : ldb / samba / talloc / etc (openSUSE-2015-943)");
  script_summary(english:"Check for the openSUSE-2015-943 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ldb, samba, talloc, tdb, tevent fixes the following
security issues and bugs :

The Samba LDB was updated to version 1.1.24 :

  - Fix ldap \00 search expression attack dos;
    CVE-2015-3223; (bso#11325)

  - Fix remote read memory exploit in ldb; CVE-2015-5330;
    (bso#11599)

  - Move ldb_(un)pack_data into ldb_module.h for testing

  - Fix installation of _ldb_text.py

  - Fix propagation of ldb errors through tdb

  - Fix bug triggered by having an empty message in database
    during search

Samba was updated to fix these issues :

  - Malicious request can cause Samba LDAP server to hang,
    spinning using CPU; CVE-2015-3223; (bso#11325);
    (bnc#958581).

  - Remote read memory exploit in LDB; CVE-2015-5330;
    (bso#11599); (bnc#958586).

  - Insufficient symlink verification (file access outside
    the share); CVE-2015-5252; (bso#11395); (bnc#958582).

  - No man in the middle protection when forcing smb
    encryption on the client side; CVE-2015-5296;
    (bso#11536); (bnc#958584).

  - Currently the snapshot browsing is not secure thru
    windows previous version (shadow_copy2); CVE-2015-5299;
    (bso#11529); (bnc#958583).

  - Fix Microsoft MS15-096 to prevent machine accounts from
    being changed into user accounts; CVE-2015-8467;
    (bso#11552); (bnc#958585).

  - Changing log level of two entries to from 1 to 3;
    (bso#9912).

  - vfs_gpfs: Re-enable share modes; (bso#11243).

  - wafsamba: Also build libraries with RELRO protection;
    (bso#11346).

  - ctdb: Strip trailing spaces from nodes file;
    (bso#11365).

  - s3-smbd: Fix old DOS client doing wildcard delete -
    gives a attribute type of zero; (bso#11452).

  - nss_wins: Do not run into use after free issues when we
    access memory allocated on the globals and the global
    being reinitialized; (bso#11563).

  - async_req: Fix non-blocking connect(); (bso#11564).

  - auth: gensec: Fix a memory leak; (bso#11565).

  - lib: util: Make non-critical message a warning;
    (bso#11566).

  - Fix winbindd crashes with samlogon for trusted domain
    user; (bso#11569); (bnc#949022).

  - smbd: Send SMB2 oplock breaks unencrypted; (bso#11570).

  - ctdb: Open the RO tracking db with perms 0600 instead of
    0000; (bso#11577).

  - manpage: Correct small typo error; (bso#11584).

  - s3: smbd: If EA's are turned off on a share don't allow
    an SMB2 create containing them; (bso#11589).

  - Backport some valgrind fixes from upstream master;
    (bso#11597).

  - s3: smbd: have_file_open_below() fails to enumerate open
    files below an open directory handle; (bso#11615).

  - docs: Fix some typos in the idmap config section of man
    5 smb.conf; (bso#11619).

  - Cleanup and enhance the pidl sub package.

  - s3: smbd: Fix our access-based enumeration on 'hide
    unreadable' to match Windows; (bso#10252).

  - smbd: Fix file name buflen and padding in notify
    repsonse; (bso#10634).

  - kerberos: Make sure we only use prompter type when
    available; (bso#11038).

  - s3:ctdbd_conn: Make sure we destroy tevent_fd before
    closing the socket; (bso#11316).

  - dcerpc.idl: accept invalid dcerpc_bind_nak pdus;
    (bso#11327).

  - Fix a deadlock in tdb; (bso#11381).

  - s3: smbd: Fix mkdir race condition; (bso#11486).

  - pam_winbind: Fix a segfault if initialization fails;
    (bso#11502).

  - s3: dfs: Fix a crash when the dfs targets are disabled;
    (bso#11509).

  - s3: smbd: Fix opening/creating :stream files on the root
    share directory; (bso#11522).

  - net: Fix a crash with 'net ads keytab create';
    (bso#11528).

  - s3: smbd: Fix a crash in unix_convert() and a NULL
    pointer bug introduced by previous 'raw' stream fix
    (bso#11522); (bso#11535).

  - vfs_fruit: Return value of ad_pack in vfs_fruit.c;
    (bso#11543).

  - vfs_commit: Set the fd on open before calling
    SMB_VFS_FSTAT; (bso#11547).

  - Fix bug in smbstatus where the lease info is not
    printed; (bso#11549).

  - s3:smbstatus: Add stream name to share_entry_forall();
    (bso#11550).

  - Prevent NULL pointer access in samlogon fallback when
    security credentials are null; (bnc#949022).

  - Fix 100% CPU in winbindd when logging in with 'user must
    change password on next logon'; (bso#11038).

talloc was updated to version 2.1.5; (bsc#954658) (bsc#951660).

  - Test that talloc magic differs between processes.

  - Increment minor version due to added
    talloc_test_get_magic.

  - Provide tests access to talloc_magic.

  - Test magic protection measures.

tdb was updated to version 1.3.8; (bsc#954658).

  - Improved python3 bindings

tevent was updated to 0.9.26; (bsc#954658).

  - New tevent_thread_proxy api

  - Minor build fixes This update was imported from the
    SUSE:SLE-12-SP1:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958586"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ldb / samba / talloc / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-atsvc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-atsvc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-atsvc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-atsvc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-atsvc0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgensec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgensec0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgensec0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgensec0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgensec0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libregistry-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libregistry0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libregistry0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libregistry0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libregistry0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-raw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-raw0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-raw0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-raw0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-raw0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pyldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pyldb-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pyldb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pyldb-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pyldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pytalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pytalloc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pytalloc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pytalloc-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pytalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tdb-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tdb-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tevent-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tevent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tevent-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:talloc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tdb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tdb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tdb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tevent-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"ldb-debugsource-1.1.24-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ldb-tools-1.1.24-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ldb-tools-debuginfo-1.1.24-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-atsvc-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-atsvc0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-atsvc0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-binding0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-binding0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-samr-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-samr0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-samr0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgensec-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgensec0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgensec0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libldb-devel-1.1.24-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libldb1-1.1.24-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libldb1-debuginfo-1.1.24-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-krb5pac-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-krb5pac0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-krb5pac0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-nbt-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-nbt0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-nbt0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-standard-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-standard0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-standard0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnetapi-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnetapi0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnetapi0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libregistry-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libregistry0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libregistry0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-credentials-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-credentials0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-credentials0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-hostconfig-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-hostconfig0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-hostconfig0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-passdb-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-passdb0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-passdb0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-policy-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-policy0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-policy0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-util-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-util0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-util0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamdb-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamdb0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamdb0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbclient-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbclient-raw-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbclient-raw0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbclient-raw0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbclient0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbclient0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbconf-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbconf0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbconf0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbldap-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbldap0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbldap0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtalloc-devel-2.1.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtalloc2-2.1.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtalloc2-debuginfo-2.1.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtdb-devel-1.3.8-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtdb1-1.3.8-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtdb1-debuginfo-1.3.8-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtevent-devel-0.9.26-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtevent-util-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtevent-util0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtevent-util0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtevent0-0.9.26-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtevent0-debuginfo-0.9.26-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwbclient-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwbclient0-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwbclient0-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pyldb-1.1.24-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pyldb-debuginfo-1.1.24-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pyldb-devel-1.1.24-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pytalloc-2.1.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pytalloc-debuginfo-2.1.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pytalloc-devel-2.1.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-tdb-1.3.8-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-tdb-debuginfo-1.3.8-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-tevent-0.9.26-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-tevent-debuginfo-0.9.26-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-client-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-client-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-core-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-debugsource-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-libs-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-libs-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-pidl-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-python-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-python-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-test-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-test-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-test-devel-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-winbind-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-winbind-debuginfo-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"talloc-debugsource-2.1.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tdb-debugsource-1.3.8-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tdb-tools-1.3.8-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tdb-tools-debuginfo-1.3.8-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tevent-debugsource-0.9.26-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc-atsvc0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc-atsvc0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc-samr0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc-samr0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgensec0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgensec0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libldb1-32bit-1.1.24-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libldb1-debuginfo-32bit-1.1.24-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr-standard0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libnetapi0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libregistry0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libregistry0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-policy0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-policy0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-util0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamdb0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbclient-raw0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbclient0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbconf0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbldap0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtalloc2-32bit-2.1.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtalloc2-debuginfo-32bit-2.1.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtdb1-32bit-1.3.8-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtdb1-debuginfo-32bit-1.3.8-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtevent-util0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtevent0-32bit-0.9.26-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtevent0-debuginfo-32bit-0.9.26-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libwbclient0-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"pyldb-32bit-1.1.24-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"pyldb-debuginfo-32bit-1.1.24-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"pytalloc-32bit-2.1.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"pytalloc-debuginfo-32bit-2.1.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"python-tdb-32bit-1.3.8-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"python-tdb-debuginfo-32bit-1.3.8-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"python-tevent-32bit-0.9.26-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"python-tevent-debuginfo-32bit-0.9.26-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-client-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-libs-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-winbind-32bit-4.2.4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.2.4-9.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldb-debugsource / ldb-tools / ldb-tools-debuginfo / libldb-devel / etc");
}
