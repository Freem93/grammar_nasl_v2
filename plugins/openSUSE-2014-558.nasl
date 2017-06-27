#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-558.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77845);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/26 14:44:46 $");

  script_cve_id("CVE-2012-3524", "CVE-2014-3477", "CVE-2014-3532", "CVE-2014-3533", "CVE-2014-3635", "CVE-2014-3636", "CVE-2014-3637", "CVE-2014-3638", "CVE-2014-3639");

  script_name(english:"openSUSE Security Update : dbus-1 (openSUSE-SU-2014:1228-1)");
  script_summary(english:"Check for the openSUSE-2014-558 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"DBUS-1 was upgraded to upstream release 1.8.

This brings the version of dbus to the latest stable release from an
unstable snapshot 1.7.4 that is know to have several regressions

  - Upstream changes since 1.7.4 :

  + Security fixes :

  - Do not accept an extra fd in the padding of a cmsg
    message, which could lead to a 4-byte heap buffer
    overrun. (CVE-2014-3635, fdo#83622; Simon McVittie)

  - Reduce default for maximum Unix file descriptors passed
    per message from 1024 to 16, preventing a uid with the
    default maximum number of connections from exhausting
    the system bus' file descriptors under Linux's default
    rlimit. Distributors or system administrators with a
    restrictive fd limit may wish to reduce these limits
    further. Additionally, on Linux this prevents a second
    denial of service in which the dbus-daemon can be made
    to exceed the maximum number of fds per sendmsg() and
    disconnect the process that would have received them.
    (CVE-2014-3636, fdo#82820; Alban Crequy)

  - Disconnect connections that still have a fd pending
    unmarshalling after a new configurable limit,
    pending_fd_timeout (defaulting to 150 seconds), removing
    the possibility of creating an abusive connection that
    cannot be disconnected by setting up a circular
    reference to a connection's file descriptor.
    (CVE-2014-3637, fdo#80559; Alban Crequy)

  - Reduce default for maximum pending replies per
    connection from 8192 to 128, mitigating an algorithmic
    complexity denial-of-service attack (CVE-2014-3638,
    fdo#81053; Alban Crequy)

  - Reduce default for authentication timeout on the system
    bus from 30 seconds to 5 seconds, avoiding denial of
    service by using up all unauthenticated connection
    slots; and when all unauthenticated connection slots are
    used up, make new connection attempts block instead of
    disconnecting them. (CVE-2014-3639, fdo#80919; Alban
    Crequy)

  - On Linux >0 2.6.37-rc4, if sendmsg() fails with
    ETOOMANYREFS, silently drop the message. This prevents
    an attack in which a malicious client can make
    dbus-daemon disconnect a system service, which is a
    local denial of service. (fdo#80163, CVE-2014-3532;
    Alban Crequy)

  - Track remaining Unix file descriptors correctly when
    more than one message in quick succession contains fds.
    This prevents another attack in which a malicious client
    can make dbus-daemon disconnect a system service.
    (fdo#79694, fdo#80469, CVE-2014-3533; Alejandro
    Mart&iacute;nez Su&aacute;rez, Simon McVittie, Alban
    Crequy)

  - Alban Crequy at Collabora Ltd. discovered and fixed a
    denial-of-service flaw in dbus-daemon, part of the
    reference implementation of D-Bus. Additionally, in
    highly unusual environments the same flaw could lead to
    a side channel between processes that should not be able
    to communicate. (CVE-2014-3477, fdo#78979)

  + Other fixes and enhancements :

  - Check for libsystemd from systemd >= 209, falling back
    to the older separate libraries if not found (Umut
    Tezduyar Lindskog, Simon McVittie)

  - On Linux, use prctl() to disable core dumps from a test
    executable that deliberately raises SIGSEGV to test
    dbus-daemon's handling of that condition (fdo#83772,
    Simon McVittie)

  - Fix compilation with --enable-stats (fdo#81043, Gentoo
    #507232; Alban Crequy)

  - Improve documentation for running tests on Windows
    (fdo#41252, Ralf Habacker)

  - When dbus-launch --exit-with-session starts a
    dbus-daemon but then cannot attach to a session, kill
    the dbus-daemon as intended (fdo#74698,
    &#x420;&#x43E;&#x43C;&#x430;&#x43D;
    &#x414;&#x43E;&#x43D;&#x447;&#x435;&#x43D;&#x43A;&#x43E;
    )

  - in the CMake build system, add some hints for Linux
    users cross-compiling Windows D-Bus binaries to be able
    to run tests under Wine (fdo#41252, Ralf Habacker)

  - add Documentation key to dbus.service (fdo#77447,
    Cameron Norman)

  - in 'dbus-uuidgen --ensure', try to copy systemd's
    /etc/machine-id to /var/lib/dbus/machine-id instead of
    generating an entirely new ID (fdo#77941, Simon
    McVittie)

  - if dbus-launch receives an X error very quickly, do not
    kill unrelated processes (fdo#74698,
    &#x420;&#x43E;&#x43C;&#x430;&#x43D;
    &#x414;&#x43E;&#x43D;&#x447;&#x435;&#x43D;&#x43A;&#x43E;
    )

  - on Windows, allow up to 8K connections to the
    dbus-daemon, instead of the previous 64 (fdo#71297;
    Cristian Onet, Ralf Habacker)

  - cope with \r\n newlines in regression tests, since on
    Windows, dbus-daemon.exe uses text mode (fdo#75863,
    &#x420;&#x443;&#x441;&#x43B;&#x430;&#x43D;
    &#x418;&#x436;&#x431;&#x443;&#x43B;&#x430;&#x442;&#x43E;
    &#x432;)

  - Enhance the CMake build system to check for GLib and
    compile/run a subset of the regression tests (fdo#41252,
    fdo#73495; Ralf Habacker)

  - don't rely on va_copy(), use DBUS_VA_COPY() wrapper
    (fdo#72840, Ralf Habacker)

  - fix compilation of systemd journal support on older
    systemd versions where sd-journal.h doesn't include
    syslog.h (fdo#73455, Ralf Habacker)

  - fix compilation on older MSVC versions by including
    stdlib.h (fdo#73455, Ralf Habacker)

  - Allow <allow_anonymous/> to appear in an included
    configuration file (fdo#73475, Matt Hoosier)

  - If the tests crash with an assertion failure, they no
    longer default to blocking for a debugger to be
    attached. Set DBUS_BLOCK_ON_ABORT in the environment if
    you want the old behaviour.

  - To improve debuggability, the dbus-daemon and
    dbus-daemon-eavesdrop tests can be run with an external
    dbus-daemon by setting DBUS_TEST_DAEMON_ADDRESS in the
    environment. Test-cases that require an
    unusually-configured dbus-daemon are skipped.

  - don't require messages with no INTERFACE to be
    dispatched (fdo#68597, Simon McVittie)

  - document 'tcp:bind=...' and 'nonce-tcp:bind=...'
    (fdo#72301, Chengwei Yang)

  - define 'listenable' and 'connectable' addresses, and
    discuss the difference (fdo#61303, Simon McVittie)

  - support printing Unix file descriptors in dbus-send,
    dbus-monitor (fdo#70592, Robert Ancell)

  - don't install systemd units if --disable-systemd is
    given (fdo#71818, Chengwei Yang)

  - don't leak memory on out-of-memory while listing
    activatable or active services (fdo#71526, Radoslaw
    Pajak)

  - fix undefined behaviour in a regression test (fdo#69924,
    DreamNik)

  - escape Unix socket addresses correctly (fdo#46013,
    Chengwei Yang)

  - on SELinux systems, don't assume that SECCLASS_DBUS,
    DBUS__ACQUIRE_SVC and DBUS__SEND_MSG are numerically
    equal to their values in the reference policy
    (fdo#88719, osmond sun)

  - define PROCESS_QUERY_LIMITED_INFORMATION if missing from
    MinGW < 4 headers (fdo#71366, Matt Fischer)

  - define WIN32_LEAN_AND_MEAN to avoid conflicts between
    winsock.h and winsock2.h (fdo#71405, Matt Fischer)

  - do not return failure from _dbus_read_nonce() with no
    error set, preventing a potential crash (fdo#72298,
    Chengwei Yang)

  - on BSD systems, avoid some O(1)-per-process memory and
    fd leaks in kqueue, preventing test failures (fdo#69332,
    fdo#72213; Chengwei Yang)

  - fix warning spam on Hurd by not trying to set
    SO_REUSEADDR on Unix sockets, which doesn't do anything
    anyway on at least Linux and FreeBSD (fdo#69492, Simon
    McVittie)

  - fix use of TCP sockets on FreeBSD and Hurd by tolerating
    EINVAL from sendmsg() with SCM_CREDS (retrying with
    plain send()), and looking for credentials more
    correctly (fdo#69492, Simon McVittie)

  - ensure that tests run with a temporary XDG_RUNTIME_DIR
    to avoid getting mixed up in XDG/systemd 'user sessions'
    (fdo#61301, Simon McVittie)

  - refresh cached policy rules for existing connections
    when bus configuration changes (fdo#39463, Chengwei
    Yang)

  - If systemd support is enabled, libsystemd-journal is now
    required.

  - When activating a non-systemd service under systemd,
    annotate its stdout/stderr with its bus name in the
    Journal. Known limitation: because the socket is opened
    before forking, the process will still be logged as if
    it had dbus-daemon's process ID and user ID. (fdo#68559,
    Chengwei Yang)

  - Document more configuration elements in dbus-daemon(1)
    (fdo#69125, Chengwei Yang)

  - Don't leak string arrays or fds if
    dbus_message_iter_get_args_valist() unpacks them and
    then encounters an error (fdo#21259, Chengwei Yang)

  - If compiled with libaudit, retain CAP_AUDIT_WRITE so we
    can write disallowed method calls to the audit log,
    fixing a regression in 1.7.6 (fdo#49062, Colin Walters)

  - path_namespace='/' in match rules incorrectly matched
    nothing; it now matches everything. (fdo#70799, Simon
    McVittie)

  - Directory change notification via dnotify on Linux is no
    longer supported; it hadn't compiled successfully since
    2010 in any case. If you don't have inotify (Linux) or
    kqueue (*BSD), you will need to send SIGHUP to the
    dbus-daemon when its configuration changes. (fdo#33001,
    Chengwei Yang)

  - Compiling with --disable-userdb-cache is no longer
    supported; it didn't work since at least 2008, and would
    lead to an extremely slow dbus-daemon even it worked.
    (fdo#15589, fdo#17133, fdo#66947; Chengwei Yang)

  - The DBUS_DISABLE_ASSERTS CMake option didn't actually
    disable most assertions. It has been renamed to
    DBUS_DISABLE_ASSERT to be consistent with the Autotools
    build system. (fdo#66142, Chengwei Yang)

  - --with-valgrind=auto enables Valgrind instrumentation if
    and only if valgrind headers are available. The default
    is still

    --with-valgrind=no. (fdo#56925, Simon McVittie)

  - Platforms with no 64-bit integer type are no longer
    supported. (fdo#65429, Simon McVittie)

  - GNU make is now (documented to be) required. (fdo#48277,
    Simon McVittie)

  - Full test coverage no longer requires dbus-glib,
    although the tests do not exercise the shared library
    (only a static copy) if dbus-glib is missing.
    (fdo#68852, Simon McVittie)

  - D-Bus Specification 0.22

  - Document GetAdtAuditSessionData() and
    GetConnectionSELinuxSecurityContext() (fdo#54445, Simon)

  - Fix example .service file (fdo#66481, Chengwei Yang)

  - Don't claim D-Bus is 'low-latency' (lower than what?),
    just give factual statements about it supporting async
    use (fdo#65141, Justin Lee)

  - Document the contents of .service files, and the fact
    that system services' filenames are constrained
    (fdo#66608; Simon McVittie, Chengwei Yang)

  - Be thread-safe by default on all platforms, even if
    dbus_threads_init_default() has not been called. For
    compatibility with older libdbus, library users should
    continue to call dbus_threads_init_default(): it is
    harmless to do so. (fdo#54972, Simon McVittie)

  - Add GetConnectionCredentials() method (fdo#54445, Simon)

  - New API: dbus_setenv(), a simple wrapper around
    setenv(). Note that this is not thread-safe. (fdo#39196,
    Simon)

  - Add dbus-send --peer=ADDRESS (connect to a given
    peer-to-peer connection, like --address=ADDRESS in
    previous versions) and dbus-send --bus=ADDRESS (connect
    to a given bus, like dbus-monitor

    --address=ADDRESS). dbus-send --address still exists for
    backwards compatibility, but is no longer documented.
    (fdo#48816, Andrey Mazo)

  - 'dbus-daemon --nofork' is allowed on Windows again.
    (fdo#68852, Simon McVittie)

  - Avoid an infinite busy-loop if a signal interrupts
    waitpid() (fdo#68945, Simon McVittie)

  - Clean up memory for parent nodes when objects are
    unexported (fdo#60176, Thomas Fitzsimmons)

  - Make dbus_connection_set_route_peer_messages(x, FALSE)
    behave as documented. Previously, it assumed its second
    parameter was TRUE. (fdo#69165, Chengwei Yang)

  - Escape addresses containing non-ASCII characters
    correctly (fdo#53499, Chengwei Yang)

  - Document <servicedir> search order correctly (fdo#66994,
    Chengwei Yang)

  - Don't crash on 'dbus-send --session / x.y.z' which
    regressed in 1.7.4. (fdo#65923, Chengwei Yang)

  - If malloc() returns NULL in _dbus_string_init() or
    similar, don't free an invalid pointer if the string is
    later freed (fdo#65959, Chengwei Yang)

  - If malloc() returns NULL in dbus_set_error(), don't
    va_end() a va_list that was never va_start()ed
    (fdo#66300, Chengwei Yang)

  - fix build failure with --enable-stats (fdo#66004,
    Chengwei Yang)

  - fix a regression test on platforms with strict alignment
    (fdo#67279, Colin Walters)

  - Avoid calling function parameters 'interface' since
    certain Windows headers have a namespace-polluting macro
    of that name (fdo#66493, Ivan Romanov)

  - Assorted Doxygen fixes (fdo#65755, Chengwei Yang)

  - Various thread-safety improvements to static variables
    (fdo#68610, Simon McVittie)

  - Make 'make -j check' work (fdo#68852, Simon McVittie)

  - Fix a NULL pointer dereference on an unlikely error path
    (fdo#69327, Sviatoslav Chagaev)

  - Improve valgrind memory pool tracking (fdo#69326,
    Sviatoslav Chagaev)

  - Don't over-allocate memory in dbus-monitor (fdo#69329,
    Sviatoslav Chagaev)

  - dbus-monitor can monitor dbus-daemon < 1.5.6 again
    (fdo#66107, Chengwei Yang)

  - If accept4() fails with EINVAL, as it can on older Linux
    kernels with newer glibc, try accept() instead of going
    into a busy-loop. (fdo#69026, Chengwei Yang)

  - If socket() or socketpair() fails with EINVAL or
    EPROTOTYPE, for instance on Hurd or older Linux with a
    new glibc, try without SOCK_CLOEXEC. (fdo#69073; Pino
    Toscano, Chengwei Yang)

  - Fix a file descriptor leak on an error code path.
    (fdo#69182, Sviatoslav Chagaev)

  - dbus-run-session: clear some unwanted environment
    variables (fdo#39196, Simon)

  - dbus-run-session: compile on FreeBSD (fdo#66197,
    Chengwei Yang)

  - Don't fail the autolaunch test if there is no DISPLAY
    (fdo#40352, Simon)

  - Use dbus-launch from the builddir for testing, not the
    installed copy (fdo#37849, Chengwei Yang)

  - Fix compilation if writev() is unavailable (fdo#69409,
    Vasiliy Balyasnyy)

  - Remove broken support for LOCAL_CREDS credentials
    passing, and document where each credential-passing
    scheme is used (fdo#60340, Simon McVittie)

  - Make autogen.sh work on *BSD by not assuming GNU
    coreutils functionality fdo#35881, fdo#69787; Chengwei
    Yang)

  - dbus-monitor: be portable to NetBSD (fdo#69842, Chengwei
    Yang)

  - dbus-launch: stop using non-portable asprintf
    (fdo#37849, Simon)

  - Improve error reporting from the setuid activation
    helper (fdo#66728, Chengwei Yang)

  - Remove unavailable command-line options from
    'dbus-daemon --help' (fdo#42441, Ralf Habacker)

  - Add support for looking up local TCPv4 clients'
    credentials on Windows XP via the undocumented
    AllocateAndGetTcpExTableFromStack function (fdo#66060,
    Ralf Habacker)

  - Fix insufficient dependency-tracking (fdo#68505, Simon
    McVittie)

  - Don't include wspiapi.h, fixing a compiler warning
    (fdo#68852, Simon McVittie)

  - add DBUS_ENABLE_ASSERT, DBUS_ENABLE_CHECKS for less
    confusing conditionals (fdo#66142, Chengwei Yang)

  - improve verbose-mode output (fdo#63047, Colin Walters)

  - consolidate Autotools and CMake build (fdo#64875, Ralf
    Habacker)

  - fix various unused variables, unusual build
    configurations etc. (fdo#65712, fdo#65990, fdo#66005,
    fdo#66257, fdo#69165, fdo#69410, fdo#70218; Chengwei
    Yang, Vasiliy Balyasnyy)

  - dbus-cve-2014-3533.patch: Add patch for CVE-2014-3533 to
    fix (fdo#63127) &bull; CVE-2012-3524: Don't access
    environment variables (fdo#52202) (fdo#51521, Dave
    Reisner) &bull; Remove an incorrect assertion from
    DBusTransport (fdo#51657, (fdo#51406, Simon McVittie)
    (fdo#51032, Simon McVittie) (fdo#34671, Simon McVittie)
    &middot; Check for libpthread under CMake on Unix
    (fdo#47237, Simon McVittie) spec-compliance (fdo#48580,
    David Zeuthen) non-root when using OpenBSD install(1)
    (fdo#48217, Antoine Jacoutot) (fdo#45896, Simon
    McVittie) (fdo#39549, Simon McVittie) invent their own
    'union of everything' type (fdo#11191, Simon find(1)
    (fdo#33840, Simon McVittie) (fdo#46273, Alban Crequy)
    again on Win32, but not on WinCE (fdo#46049, Simon
    (fdo#47321, Andoni Morales Alastruey) (fdo#39231,
    fdo#41012; Simon McVittie)

  - Add a regression test for fdo#38005 (fdo#39836, Simon
    McVittie) a service file entry for activation
    (fdo#39230, Simon McVittie) (fdo#24317, #34870; Will
    Thompson, David Zeuthen, Simon McVittie) and document it
    better (fdo#31818, Will Thompson) &bull; Let the bus
    daemon implement more than one interface (fdo#33757,
    &bull; Optimize _dbus_string_replace_len to reduce waste
    (fdo#21261, (fdo#35114, Simon McVittie) &bull; Add
    dbus_type_is_valid as public API (fdo#20496, Simon
    McVittie) to unknown interfaces in the bus daemon
    (fdo#34527, Lennart Poettering) (fdo#32245; Javier
    Jard&oacute;n, Simon McVittie) &bull; Correctly give
    XDG_DATA_HOME priority over XDG_DATA_DIRS (fdo#34496, in
    embedded environments (fdo#19997, NB#219964; Simon
    McVittie) &bull; Install the documentation, and an index
    for Devhelp (fdo#13495, booleans when sending them
    (fdo#16338, NB#223152; Simon McVittie) errors to
    dbus-shared.h (fdo#34527, Lennart Poettering) data
    (fdo#10887, Simon McVittie) .service files (fdo#19159,
    Sven Herzberg) (fdo#35750, Colin Walters) (fdo#32805,
    Mark Brand) which could result in a busy-loop
    (fdo#32992, NB#200248; possibly &bull; Fix failure to
    detect abstract socket support (fdo#29895) (fdo#32262,
    NB#180486) &bull; Improve some error code paths
    (fdo#29981, fdo#32264, fdo#32262, fdo#33128, fdo#33277,
    fdo#33126, NB#180486) &bull; Avoid possible symlink
    attacks in /tmp during compilation (fdo#32854) &bull;
    Tidy up dead code (fdo#25306, fdo#33128, fdo#34292,
    NB#180486) &bull; Improve gcc malloc annotations
    (fdo#32710) &bull; Documentation improvements
    (fdo#11190) &bull; Avoid readdir_r, which is difficult
    to use correctly (fdo#8284, fdo#15922, LP#241619) &bull;
    Cope with invalid files in session.d, system.d
    (fdo#19186, &bull; Don't distribute generated files that
    embed our builddir (fdo#30285, fdo#34292) (fdo#33474,
    LP#381063) with lcov HTML reports and
    --enable-compiler-coverage (fdo#10887) &middot; support
    credentials-passing (fdo#32542) &middot; opt-in to
    thread safety (fdo#33464)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-09/msg00038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=896453"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dbus-1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-1.8.8-4.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-debuginfo-1.8.8-4.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-debugsource-1.8.8-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-devel-1.8.8-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-x11-1.8.8-4.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-x11-debuginfo-1.8.8-4.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-x11-debugsource-1.8.8-4.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdbus-1-3-1.8.8-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdbus-1-3-debuginfo-1.8.8-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"dbus-1-debuginfo-32bit-1.8.8-4.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"dbus-1-devel-32bit-1.8.8-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdbus-1-3-32bit-1.8.8-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdbus-1-3-debuginfo-32bit-1.8.8-4.20.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus-1");
}
