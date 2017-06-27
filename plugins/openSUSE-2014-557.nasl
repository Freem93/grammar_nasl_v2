#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-557.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77890);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/03 14:00:06 $");

  script_cve_id("CVE-2013-2168", "CVE-2014-3477", "CVE-2014-3532", "CVE-2014-3533", "CVE-2014-3635", "CVE-2014-3636", "CVE-2014-3637", "CVE-2014-3638", "CVE-2014-3639");

  script_name(english:"openSUSE Security Update : dbus-1 (openSUSE-SU-2014:1239-1)");
  script_summary(english:"Check for the openSUSE-2014-557 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The DBUS-1 service and libraries were updated to upstream release
1.6.24 fixing security issues and bugs.

Upstream changes since dbus 1.6.8

  + Security fixes

  - Do not accept an extra fd in the padding of a cmsg
    message, which could lead to a 4-byte heap buffer
    overrun. (CVE-2014-3635, fdo#83622; Simon McVittie)

  - Reduce default for maximum Unix file descriptors passed
    per message from 1024 to 16, preventing a uid with the
    default maximum number of connections from exhausting
    the system bus' file descriptors under Linux's default
    rlimit. Distributors or system administrators with a
    more restrictive fd limit may wish to reduce these
    limits further. Additionally, on Linux this prevents a
    second denial of service in which the dbus-daemon can be
    made to exceed the maximum number of fds per sendmsg()
    and disconnect the process that would have received
    them. (CVE-2014-3636, fdo#82820; Alban Crequy)

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

  - On Linux >= 2.6.37-rc4, if sendmsg() fails with
    ETOOMANYREFS, silently drop the message. This prevents
    an attack in which a malicious client can make
    dbus-daemon disconnect a system service, which is a
    local denial of service. (fdo#80163, CVE-2014-3532;
    Alban Crequy)

  - Track remaining Unix file descriptors correctly when
    more than one message in quick succession contains fds.
    This prevents another attack which a malicious client
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

  - CVE-2013-2168: Fix misuse of va_list that could be used
    as a denial of service for system services.
    Vulnerability reported by Alexandru Cornea. (Simon)

  + Other fixes

  - Don't leak memory on out-of-memory while listing
    activatable or active services (fdo#71526, Radoslaw
    Pajak)

  - fix undefined behaviour in a regression test (fdo#69924,
    DreamNik)

  - path_namespace='/' in match rules incorrectly matched
    nothing; it now matches everything. (fdo#70799, Simon
    McVittie)

  - Make dbus_connection_set_route_peer_messages(x, FALSE)
    behave as documented. Previously, it assumed its second
    parameter was TRUE. (fdo#69165, Chengwei Yang)

  - Fix a NULL pointer dereference on an unlikely error path
    (fdo#69327, Sviatoslav Chagaev)

  - If accept4() fails with EINVAL, as it can on older Linux
    kernels with newer glibc, try accept() instead of going
    into a busy-loop. (fdo#69026, Chengwei Yang)

  - If socket() or socketpair() fails with EINVAL or
    EPROTOTYPE, for instance on Hurd or older Linux with a
    new glibc, try without SOCK_CLOEXEC. (fdo#69073; Pino
    Toscano, Chengwei Yang)

  - Fix a file descriptor leak on an error code path.
    (fdo#69182, Sviatoslav Chagaev)

  - Fix compilation if writev() is unavailable (fdo#69409,
    Vasiliy Balyasnyy)

  - Avoid an infinite busy-loop if a signal interrupts
    waitpid() (fdo#68945, Simon McVittie)

  - Escape addresses containing non-ASCII characters
    correctly (fdo#53499, Chengwei Yang)

  - If malloc() returns NULL in _dbus_string_init() or
    similar, don't free an invalid pointer if the string is
    later freed (fdo#65959, Chengwei Yang)

  - If malloc() returns NULL in dbus_set_error(), don't
    va_end() a va_list that was never va_start()ed
    (fdo#66300, Chengwei Yang)

  - Fix a regression test on platforms with strict alignment
    (fdo#67279, Colin Walters)

  - Avoid calling function parameters 'interface' since
    certain Windows headers have a namespace-polluting macro
    of that name (fdo#66493, Ivan Romanov)

  - Make 'make -j check' work (fdo#68852, Simon McVittie)

  - In dbus-daemon, don't crash if a .service file starts
    with key=value (fdo#60853, Chengwei Yang)

  - Fix an assertion failure if we try to activate systemd
    services before systemd connects to the bus (fdo#50199,
    Chengwei Yang)

  - Avoid compiler warnings for ignoring the return from
    write() (Chengwei Yang)

  - Following Unicode Corrigendum #9, the noncharacters
    U+nFFFE, U+nFFFF, U+FDD0..U+FDEF are allowed in UTF-8
    strings again. (fdo#63072, Simon McVittie)

  - Diagnose incorrect use of dbus_connection_get_data()
    with negative slot (i.e. before allocating the slot)
    rather than returning junk (fdo#63127, Dan Williams)

  - In the activation helper, when compiled for tests, do
    not reset the system bus address, fixing the regression
    tests. (fdo#52202, Simon)

  - Fix building with Valgrind 3.8, at the cost of causing
    harmless warnings with Valgrind 3.6 on some compilers
    (fdo#55932, Arun Raghavan)

  - Don't leak temporary fds pointing to /dev/null
    (fdo#56927, Michel HERMIER)

  - Create session.d, system.d directories under CMake
    (fdo#41319, Ralf Habacker)

  - Include alloca.h for alloca() if available, fixing
    compilation on Solaris 10 (fdo#63071, Dagobert
    Michelsen)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-09/msg00049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=896453"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dbus-1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-32bit");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-1.6.24-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-debuginfo-1.6.24-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-debugsource-1.6.24-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-devel-1.6.24-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-x11-1.6.24-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-x11-debuginfo-1.6.24-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-x11-debugsource-1.6.24-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libdbus-1-3-1.6.24-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libdbus-1-3-debuginfo-1.6.24-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"dbus-1-32bit-1.6.24-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"dbus-1-debuginfo-32bit-1.6.24-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"dbus-1-devel-32bit-1.6.24-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libdbus-1-3-32bit-1.6.24-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libdbus-1-3-debuginfo-32bit-1.6.24-2.26.1") ) flag++;

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
