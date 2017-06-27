#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-228.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75301);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-4496", "CVE-2013-6442");

  script_name(english:"openSUSE Security Update : samba (openSUSE-SU-2014:0404-1)");
  script_summary(english:"Check for the openSUSE-2014-228 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Samba was updated to 4.1.6, fixing bugs and security issues :

  - Password lockout not enforced for SAMR password changes,
    this allowed brute forcing of passwords; CVE-2013-4496;
    (bnc#849224).

  - smbcacls can remove a file or directory ACL by mistake;
    CVE-2013-6442; (bnc#855866).

Also the following bugs were fixed :

  - Call update-apparmor-samba-profile via ExecStartPre too;
    (bnc#867665).

  - Retry named pipe open requests on
    STATUS_PIPE_NOT_AVAILABLE; (bso#10484); (bnc#865095).

  - Propagate snapshot enumeration permissions errors to SMB
    clients; (bnc#865641).

  - Properly handle empty 'requires_membership_of' entries
    in /etc/security/pam_winbind.conf; (bnc#865771).

  - Fix problem with server taking too long to respond to a
    MSG_PRINTER_DRVUPGRADE message; (bso#9942);
    (bnc#863748).

  - Fix memory leak in printer_list_get_printer();
    (bso#9993); (bnc#865561).

  - Fix stream_depot VFS module on Btrfs; (bso#10467);
    (bnc#865397).

  - Use libarchive to provide improved smbclient tarmode
    functionality; (bso#9667); (bnc#861135).

  - Depend on %version-%release with all manual Provides and
    Requires; (bnc#844307).

  - Update to 4.1.5.

  + Fix 100% CPU utilization in winbindd when trying to free
    memory in winbindd_reinit_after_fork; (bso#10358);
    (bnc#786677).

  + smbd: Fix memory overwrites; (bso#10415).

  + s3-winbind: Improve performance of
    wb_fill_pwent_sid2uid_done(); (bso#2191).

  + ntlm_auth sometimes returns the wrong username to
    mod_ntlm_auth_winbind; (bso#10087).

  + s3: smbpasswd: Fix crashes on invalid input;
    (bso#10320).

  + s3: vfs_dirsort module: Allow dirsort to work when
    multiple simultaneous directories are open; (bso#10406).

  + Add support for Heimdal's unified krb5 and hdb plugin
    system, cope with first element in hdb_method having a
    different name in different heimdal versions and fix
    INTERNAL ERROR: Signal 11 in the kdc pid; (bso#10418).

  + vfs_btrfs: Fix incorrect zero length server-side copy
    request handling; (bso#10424).

  + s3: modules: streaminfo: As we have no VFS function
    SMB_VFS_LLISTXATTR we can't cope with a symlink when
    lp_posix_pathnames() is true; (bso#10429).

  + smbd: Fix an ancient oplock bug; (bso#10436).

  + Fix crash bug in smb2_notify code; (bso#10442).

  - Remove superfluous obsoletes *-64bit in the ifarch ppc64
    case; (bnc#437293).

  - Migrate @GMT token parsing functionality into
    vfs_snapper; (bnc#863079).

  + Improve vfs_snapper documentation.

  - Fix Winbind 100% CPU utilization caused by domain list
    corruption; (bso#10358); (bnc#786677).

  - Fix memory overwrite in FSCTL_VALIDATE_NEGOTIATE_INFO
    handler; (bso#10415); (bnc#862370).

  - Streamline the vendor suffix handling and add support
    for SLE 12.

  - Fix zero length server-side copy request handling;
    (bso#10424); (bnc#862558).

  - Set the PID directory to /run/samba on post-12.2
    systems.

  - Make use of the tmpfilesdir macro while calling
    systemd-tmpfiles.

  - Make winbindd print the interface version when it gets
    an INTERFACE_VERSION request; (bnc#726937).

  - Fix vfs_btrfs build on older platforms with duplicate
    WRITE_FLUSH definitions; (bnc#860832).

  - Check for NULL gensec_security in
    gensec_security_by_auth_type(); (bnc#860809).

  - Ensure ndr table initialization; (bnc#860648).

  - Add File Server Remote VSS Protocol (FSRVP) server for
    SMB share shadow-copies; (fate#313346).

  - s3-dir: Fix the DOS clients against 64-bit smbd's;
    (bso#2662).

  - shadow_copy2: module 'Previous Version' not working in
    Windows 7; (bso#10259).

  - s3-passdb: Fix string duplication to pointers;
    (bso#10367).

  - vfs/glusterfs: in case atime is not passed, set it to
    the current atime; (bso#10384)

  - s3: winbindd: Move calling setup_domain_child() into
    add_trusted_domain(); (bso#10358); (bnc#786677).

  - Default sysconfig daemon options to -D; (bso#10388);
    (bnc#857454).

  - Add /var/cache/samba to the client file list;
    (bnc#846586).

  - Really add the WINBINDDOPTIONS sysconfig variable on
    install; (bnc#857454).

  - Correct sysconfig variable names by adding the missing D
    char; (bnc#857454).

  - Update to 4.1.4.

  + Fix segfault in smbd; (bso#10284).

  + Fix SMB2 server panic when a smb2 brlock times out;
    (bso#10311).

  - Call stop_on_removal from preun and restart_on_update
    and insserv_cleanup from postun on pre-12.3 systems
    only; (bnc#857454).

  - BuildRequire gamin-devel instead of unmaintained
    fam-devel package on post-12.1 systems.

  - smbd: allow updates on directory write times on open
    handles; (bso#9870).

  - lib/util: use proper include for struct stat;
    (bso#10276).

  - s3:winbindd fix use of uninitialized variables;
    (bso#10280).

  - s3-winbindd: Fix DEBUG statement in
    winbind_msg_offline(); (bso#10285).

  - s3-lib: Fix %G substitution for domain users in smbd;
    (bso#10286).

  - smbd: Always use UCF_PREP_CREATEFILE for
    filename_convert calls to resolve a path for open;
    (bso#10297).

  - smb2_server processing overhead; (bso#10298).

  - ldb: bad if test in ldb_comparison_fold(); (bso#10305).

  - Fix AIO with SMB2 and locks; (bso#10310).

  - smbd: Fix a panic when a smb2 brlock times out;
    (bso#10311).

  - vfs_glusterfs: Enable per client log file; (bso#10337).

  - Add /etc/sysconfig/samba to the main and winbind
    package; (bnc#857454).

  - Create /var/run/samba with systemd-tmpfiles on post-12.2
    systems; (bnc#856759).

  - Fix broken rc{nmb,smb,winbind} sym links which should
    point to the service binary on post-12.2 systems;
    (bnc#856759).

  - Add Snapper VFS module for snapshot manipulation;
    (fate#313347).

  + dbus-1-devel required at build time.

  - Add File Server Remote VSS Protocol (FSRVP) client for
    SMB share shadow-copies; (fate#313345).

  - Do not BuildRequire perl ExtUtils::MakeMaker and
    Parse::Yapp as they're part of the minimum build
    environment.

  - Allow smbcacls to take a '--propagate-inheritance' flag
    to indicate that the add, delete, modify and set
    operations now support automatic propagation of
    inheritable ACE(s); (FATE#316474)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00062.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=437293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=844307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=846586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=855866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=856759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=857454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=861135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=862370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=862558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=867665"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpdb0-debuginfo-32bit");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo-32bit");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-atsvc-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-atsvc0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-atsvc0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-binding0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-binding0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-samr-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-samr0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-samr0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgensec-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgensec0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgensec0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-krb5pac-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-krb5pac0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-krb5pac0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-nbt-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-nbt0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-nbt0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-standard-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-standard0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-standard0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libnetapi-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libnetapi0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libnetapi0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpdb-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpdb0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpdb0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libregistry-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libregistry0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libregistry0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-credentials-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-credentials0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-credentials0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-hostconfig-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-hostconfig0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-hostconfig0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-policy-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-policy0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-policy0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-util-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-util0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-util0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamdb-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamdb0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamdb0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbclient-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbclient-raw-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbclient-raw0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbclient-raw0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbclient0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbclient0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbconf-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbconf0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbconf0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbldap-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbldap0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbldap0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbsharemodes-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbsharemodes0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbsharemodes0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtevent-util-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtevent-util0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtevent-util0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libwbclient-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libwbclient0-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libwbclient0-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-client-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-client-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-core-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-debugsource-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-libs-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-libs-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-pidl-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-python-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-python-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-test-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-test-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-test-devel-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-winbind-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-winbind-debuginfo-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc-atsvc0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc-atsvc0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc-samr0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc-samr0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgensec0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgensec0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr-standard0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libnetapi0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpdb0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpdb0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libregistry0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libregistry0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-policy0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-policy0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-util0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamdb0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbclient-raw0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbclient0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbconf0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbldap0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libtevent-util0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libwbclient0-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-client-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-libs-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-winbind-32bit-4.1.6-3.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.1.6-3.18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
