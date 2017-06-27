#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-945.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87622);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-3223", "CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299", "CVE-2015-5330", "CVE-2015-7540", "CVE-2015-8467");

  script_name(english:"openSUSE Security Update : samba / ldb / talloc / etc (openSUSE-2015-945)");
  script_summary(english:"Check for the openSUSE-2015-945 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ldb, samba, talloc, tdb, tevent fixes the following
issues :

ldb was updated to 1.1.24.

  + Fix ldap \00 search expression attack dos;
    cve-2015-3223; (bso#11325)

  + Fix remote read memory exploit in ldb; cve-2015-5330;
    (bso#11599)

  + Move ldb_(un)pack_data into ldb_module.h for testing

  + Fix installation of _ldb_text.py

  + Fix propagation of ldb errors through tdb

  + Fix bug triggered by having an empty message in database
    during search

  + Test improvements

  + Improved python bindings

  + Validate_ldb of string(generalized-time) does not accept
    millisecond format '.000Z'; (bso#9810)

  + Fix logic in ldb_val_to_time()

  + Allow to register extended match rules

  + Fixes for segfaults in pyldb

  + Documentation fixes

  + Build system improvements

  + Fix a typo in the comment, ldb_flags_mod_xxx ->
    ldb_flag_mod_xxx

  + Fix check for third_party

  + Make the successful ldb_transaction_start() message
    clearer

  + Ldb-samba: fix a memory leak in
    ldif_canonicalise_objectcategory()

  + Ldb-samba: move pyldb-utils dependency to
    python_samba__ldb

  + Build: improve detection of srcdir

Samba was updated to 4.1.22.

  + Malicious request can cause samba ldap server to hang,
    spinning using cpu; CVE-2015-3223; (bso#11325);
    (boo#958581).

  + Remote read memory exploit in ldb; cve-2015-5330;
    (bso#11599); (boo#958586).

  + Insufficient symlink verification (file access outside
    the share); CVE-2015-5252; (bso#11395); (boo#958582).

  + No man in the middle protection when forcing smb
    encryption on the client side; CVE-2015-5296;
    (bso#11536); (boo#958584).

  + Currently the snapshot browsing is not secure thru
    windows previous version (shadow_copy2); CVE-2015-5299;
    (bso#11529); (boo#958583).

  + Fix microsoft ms15-096 to prevent machine accounts from
    being changed into user accounts; CVE-2015-8467;
    (bso#11552); (boo#958585).

  + Fix remote dos in samba (ad) ldap server; cve-2015-7540;
    (bso#9187); (boo#958580).

  + Ensure attempt to ssh into locked account triggers 'Your
    account is disabled.....' to the console; (boo#953382).

  + Prevent NULL pointer access in samlogon fallback when
    security credentials are null; (boo#949022).

talloc was updated to 2.1.5; (boo#954658).

  + Minor build fixes

  + Point ld_library_path to the just-built libraries while
    calling make test.

  + Disable rpath-install and silent-rules while configure.

  + Update to 2.1.4; (boo#951660).

  + Test that talloc magic differs between processes.

  + Increment minor version due to added
    talloc_test_get_magic.

  + Provide tests access to talloc_magic.

  + Test magic protection measures.

  + Update the samba library distribution key file
    'talloc.keyring'; (bso#945116).

  + Update to 2.1.3; (boo#939051).

  + Improved python3 bindings

  + Documentation fixes regarding talloc_reference() and
    talloc_unlink()

tdb was updated to version 1.3.8; (boo#954658).

  + Fix broken build with --disable-python

  + Minor build fixes

  + Disable rpath-install and silent-rules while configure.

  + Update the samba library distribution key file
    'tdb.keyring'; (bso#945116).

  + Update to version 1.3.7.

  + First fix deadlock in the interaction between fcntl and
    mutex locking; (bso#11381)

  + Improved python3 bindings

  + Update to version 1.3.6.

  + Fix runtime detection for robust mutexes in the
    standalone build; (bso#11326).

  + Possible fix for the build with robust mutexes on
    solaris 11; (bso#11319).

  + Update to version 1.3.5.

  + Abi change: tdb_chainlock_read_nonblock() has been
    added, a nonblock variant of tdb_chainlock_read()

  + Do not build test binaries if it's not a standalone
    build

  + Fix cid 1034842 resource leak

  + Fix cid 1034841 resource leak

  + Don't let tdb_wrap_open() segfault with name==null

  + Update to version 1.3.4.

  + Toos: allow transactions with tdb_mutex_locking

  + Test: add tdb1-run-mutex-transaction1 test

  + Allow transactions on on tdb's with tdb_mutex_locking

  + Update to version 1.3.3.

  + Test: tdb_clear_if_first | tdb_mutex_locking, o_rdonly
    is a valid combination

  + Update to version 1.3.2.

  + Allow tdb_open_ex() with o_rdonly of
    tdb_feature_flag_mutex tdbs.

  + Fix a comment

  + Fix tdb_runtime_check_for_robust_mutexes()

  + Improve wording in a comment

  + Tdb.h needs bool type; obsoletes
    include_stdbool_bso10625.patch

  + Tdb_wrap: make mutexes easier to use

  + Tdb_wrap: only pull in samba-debug

  + Tdb_wrap: standalone compile without includes.h

  + Tdb_wrap: tdb_wrap.h doesn't need struct
    loadparm_context

  - Update to version 1.3.1.

  + Tools: fix a compiler warning

  + Defragment the freelist in tdb_allocate_from_freelist()

  + Add 'freelist_size' sub-command to tdbtool

  + Use tdb_freelist_merge_adjacent in tdb_freelist_size()

  + Add tdb_freelist_merge_adjacent()

  + Add utility function check_merge_ptr_with_left_record()

  + Simplify tdb_free() using check_merge_with_left_record()

  + Add utility function check_merge_with_left_record()

  + Improve comments for tdb_free().

  + Factor merge_with_left_record() out of tdb_free()

  + Fix debug message in tdb_free()

  + Reduce indentation in tdb_free() for merging left

  + Increase readability of read_record_on_left()

  + Factor read_record_on_left() out of tdb_free()

  + Build: improve detection of srcdir.

tevent was update to version 0.9.26; (boo#954658).

  + New tevent_thread_proxy api

  + Minor build fixes

  + Update the samba library distribution key file
    'tevent.keyring'; (bso#945116).

  + Update to 0.9.25.

  + Fix compile error in solaris ports backend.

  + Fix access after free in tevent_common_check_signal();
    (bso#11308).

  + Improve pytevent bindings.

  + Testsuite fixes.

  + Improve the documentation of the tevent_add_fd()
    assumtions. it must be talloc_free'ed before closing the
    fd! (bso##11141); (bso#11316).

  + Update to 0.9.24.

  + Ignore unexpected signal events in the same way the
    epoll backend does.

  + Update to 0.9.23.

  + Update the tevent_data.dox tutrial stuff to fix some
    errors, including white space problems.

  + Use tevent_req_simple_recv_unix in a few places.

  + Update to 0.9.22.

  + Remove unused exit_code in tevent_select.c

  + Remove unused exit_code in tevent_poll.c

  + Build: improve detection of srcdir

  + Lib: tevent: make tevent_sig_increment atomic.

  + Update flags in tevent pkgconfig file

  + Utilize doxygen to generate the api documentation and
    package it."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939051"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958580"
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
    value:"Update the affected samba / ldb / talloc / etc packages."
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/24");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"ldb-debugsource-1.1.24-3.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ldb-tools-1.1.24-3.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ldb-tools-debuginfo-1.1.24-3.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-atsvc-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-atsvc0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-atsvc0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-binding0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-binding0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-samr-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-samr0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc-samr0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdcerpc0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgensec-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgensec0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgensec0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libldb-devel-1.1.24-3.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libldb1-1.1.24-3.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libldb1-debuginfo-1.1.24-3.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-krb5pac-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-krb5pac0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-krb5pac0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-nbt-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-nbt0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-nbt0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-standard-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-standard0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr-standard0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libndr0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libnetapi-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libnetapi0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libnetapi0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpdb-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpdb0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpdb0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libregistry-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libregistry0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libregistry0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-credentials-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-credentials0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-credentials0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-hostconfig-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-hostconfig0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-hostconfig0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-policy-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-policy0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-policy0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-util-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-util0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamba-util0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamdb-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamdb0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsamdb0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbclient-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbclient-raw-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbclient-raw0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbclient-raw0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbclient0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbclient0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbconf-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbconf0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbconf0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbldap-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbldap0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbldap0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbsharemodes-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbsharemodes0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsmbsharemodes0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtalloc-devel-2.1.5-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtalloc2-2.1.5-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtalloc2-debuginfo-2.1.5-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtdb-devel-1.3.8-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtdb1-1.3.8-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtdb1-debuginfo-1.3.8-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtevent-devel-0.9.26-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtevent-util-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtevent-util0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtevent-util0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtevent0-0.9.26-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtevent0-debuginfo-0.9.26-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libwbclient-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libwbclient0-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libwbclient0-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pyldb-1.1.24-3.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pyldb-debuginfo-1.1.24-3.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pyldb-devel-1.1.24-3.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pytalloc-2.1.5-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pytalloc-debuginfo-2.1.5-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pytalloc-devel-2.1.5-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-tdb-1.3.8-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-tdb-debuginfo-1.3.8-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-tevent-0.9.26-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-tevent-debuginfo-0.9.26-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-client-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-client-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-core-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-debugsource-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-libs-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-libs-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-pidl-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-python-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-python-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-test-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-test-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-test-devel-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-winbind-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"samba-winbind-debuginfo-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"talloc-debugsource-2.1.5-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tdb-debugsource-1.3.8-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tdb-tools-1.3.8-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tdb-tools-debuginfo-1.3.8-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tevent-debugsource-0.9.26-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc-atsvc0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc-atsvc0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc-samr0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc-samr0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgensec0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgensec0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libldb1-32bit-1.1.24-3.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libldb1-debuginfo-32bit-1.1.24-3.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr-standard0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libnetapi0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpdb0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpdb0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libregistry0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libregistry0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-policy0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-policy0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-util0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamdb0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbclient-raw0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbclient0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbconf0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbldap0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libtalloc2-32bit-2.1.5-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libtalloc2-debuginfo-32bit-2.1.5-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libtdb1-32bit-1.3.8-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libtdb1-debuginfo-32bit-1.3.8-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libtevent-util0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libtevent0-32bit-0.9.26-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libtevent0-debuginfo-32bit-0.9.26-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libwbclient0-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"pyldb-32bit-1.1.24-3.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"pyldb-debuginfo-32bit-1.1.24-3.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"pytalloc-32bit-2.1.5-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"pytalloc-debuginfo-32bit-2.1.5-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python-tdb-32bit-1.3.8-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python-tdb-debuginfo-32bit-1.3.8-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python-tevent-32bit-0.9.26-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python-tevent-debuginfo-32bit-0.9.26-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-client-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-libs-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-winbind-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.1.22-3.46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ldb-debugsource-1.1.24-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ldb-tools-1.1.24-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ldb-tools-debuginfo-1.1.24-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-atsvc-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-atsvc0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-atsvc0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-binding0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-binding0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-samr-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-samr0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-samr0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgensec-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgensec0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgensec0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libldb-devel-1.1.24-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libldb1-1.1.24-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libldb1-debuginfo-1.1.24-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-krb5pac-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-krb5pac0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-krb5pac0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-nbt-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-nbt0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-nbt0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-standard-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-standard0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-standard0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libnetapi-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libnetapi0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libnetapi0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpdb-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpdb0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpdb0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libregistry-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libregistry0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libregistry0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-credentials-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-credentials0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-credentials0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-hostconfig-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-hostconfig0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-hostconfig0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-policy-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-policy0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-policy0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-util-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-util0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-util0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamdb-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamdb0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamdb0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbclient-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbclient-raw-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbclient-raw0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbclient-raw0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbclient0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbclient0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbconf-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbconf0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbconf0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbldap-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbldap0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbldap0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbsharemodes-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbsharemodes0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbsharemodes0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtalloc-devel-2.1.5-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtalloc2-2.1.5-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtalloc2-debuginfo-2.1.5-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtdb-devel-1.3.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtdb1-1.3.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtdb1-debuginfo-1.3.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtevent-devel-0.9.26-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtevent-util-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtevent-util0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtevent-util0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtevent0-0.9.26-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtevent0-debuginfo-0.9.26-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwbclient-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwbclient0-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwbclient0-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pyldb-1.1.24-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pyldb-debuginfo-1.1.24-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pyldb-devel-1.1.24-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pytalloc-2.1.5-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pytalloc-debuginfo-2.1.5-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pytalloc-devel-2.1.5-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-tdb-1.3.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-tdb-debuginfo-1.3.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-tevent-0.9.26-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-tevent-debuginfo-0.9.26-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-client-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-client-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-core-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-debugsource-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-libs-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-libs-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-pidl-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-python-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-python-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-test-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-test-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-test-devel-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-winbind-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-winbind-debuginfo-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"talloc-debugsource-2.1.5-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tdb-debugsource-1.3.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tdb-tools-1.3.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tdb-tools-debuginfo-1.3.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tevent-debugsource-0.9.26-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc-atsvc0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc-atsvc0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc-samr0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc-samr0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgensec0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgensec0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libldb1-32bit-1.1.24-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libldb1-debuginfo-32bit-1.1.24-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr-standard0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libnetapi0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpdb0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpdb0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libregistry0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libregistry0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-policy0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-policy0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-util0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamdb0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbclient-raw0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbclient0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbconf0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbldap0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtalloc2-32bit-2.1.5-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtalloc2-debuginfo-32bit-2.1.5-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtdb1-32bit-1.3.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtdb1-debuginfo-32bit-1.3.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtevent-util0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtevent0-32bit-0.9.26-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtevent0-debuginfo-32bit-0.9.26-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libwbclient0-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"pyldb-32bit-1.1.24-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"pyldb-debuginfo-32bit-1.1.24-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"pytalloc-32bit-2.1.5-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"pytalloc-debuginfo-32bit-2.1.5-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"python-tdb-32bit-1.3.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"python-tdb-debuginfo-32bit-1.3.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"python-tevent-32bit-0.9.26-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"python-tevent-debuginfo-32bit-0.9.26-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-client-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-libs-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-winbind-32bit-4.1.22-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.1.22-21.1") ) flag++;

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
