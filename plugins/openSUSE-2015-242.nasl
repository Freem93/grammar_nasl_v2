#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-242.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81946);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/20 13:22:39 $");

  script_cve_id("CVE-2015-1782");

  script_name(english:"openSUSE Security Update : libssh2_org (openSUSE-2015-242)");
  script_summary(english:"Check for the openSUSE-2015-242 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libssh2_org was updated to version 1.5.0 to fix bugs and a security
issue.

Changes in 1.5.0: Added Windows Cryptography API: Next Generation
based backend

Bug fixes :

  - Security Advisory: Using `SSH_MSG_KEXINIT` data
    unbounded, CVE-2015-1782

  - missing _libssh2_error in _libssh2_channel_write

  - knownhost: Fix DSS keys being detected as unknown.

  - knownhost: Restore behaviour of
    `libssh2_knownhost_writeline` with short buffer.

  - libssh2.h: on Windows, a socket is of type SOCKET, not
    int

  - libssh2_priv.h: a 1 bit bit-field should be unsigned

  - windows build: do not export externals from static
    library

  - Fixed two potential use-after-frees of the payload
    buffer

  - Fixed a few memory leaks in error paths

  - userauth: Fixed an attempt to free from stack on error

  - agent_list_identities: Fixed memory leak on OOM

  - knownhosts: Abort if the hosts buffer is too small

  - sftp_close_handle: ensure the handle is always closed

  - channel_close: Close the channel even in the case of
    errors

  - docs: added missing libssh2_session_handshake.3 file

  - docs: fixed a bunch of typos

  - userauth_password: pass on the underlying error code

  - _libssh2_channel_forward_cancel: accessed struct after
    free

  - _libssh2_packet_add: avoid using uninitialized memory

  - _libssh2_channel_forward_cancel: avoid memory leaks on
    error

  - _libssh2_channel_write: client spins on write when
    window full

  - windows build: fix build errors

  - publickey_packet_receive: avoid junk in returned
    pointers

  - channel_receive_window_adjust: store windows size always

  - userauth_hostbased_fromfile: zero assign to avoid
    uninitialized use

  - configure: change LIBS not LDFLAGS when checking for
    libs

  - agent_connect_unix: make sure there's a trailing zero

  - MinGW build: Fixed redefine warnings.

  - sftpdir.c: added authentication method detection.

  - Watcom build: added support for WinCNG build.

  - configure.ac: replace AM_CONFIG_HEADER with
    AC_CONFIG_HEADERS

  - sftp_statvfs: fix for servers not supporting statfvs
    extension

  - knownhost.c: use LIBSSH2_FREE macro instead of free

  - Fixed compilation using mingw-w64

  - knownhost.c: fixed that 'key_type_len' may be used
    uninitialized

  - configure: Display individual crypto backends on
    separate lines

  - examples on Windows: check for WSAStartup return code

  - examples on Windows: check for socket return code

  - agent.c: check return code of MapViewOfFile

  - kex.c: fix possible NULL pointer de-reference with
    session->kex

  - packet.c: fix possible NULL pointer de-reference within
    listen_state

  - tests on Windows: check for WSAStartup return code

  - userauth.c: improve readability and clarity of for-loops

  - examples on Windows: use native SOCKET-type instead of
    int

  - packet.c: i < 256 was always true and i would overflow
    to 0

  - kex.c: make sure mlist is not set to NULL

  - session.c: check return value of session_nonblock in
    debug mode

  - session.c: check return value of session_nonblock during
    startup

  - userauth.c: make sure that sp_len is positive and avoid
    overflows

  - knownhost.c: fix use of uninitialized argument variable
    wrote

  - openssl: initialise the digest context before calling
    EVP_DigestInit()

  - libssh2_agent_init: init ->fd to LIBSSH2_INVALID_SOCKET

  - configure.ac: Add zlib to Requires.private in libssh2.pc
    if using zlib

  - configure.ac: Rework crypto library detection

  - configure.ac: Reorder --with-* options in --help output

  - configure.ac: Call zlib zlib and not libz in text but
    keep option names

  - Fix non-autotools builds: Always define the
    LIBSSH2_OPENSSL CPP macro

  - sftp: seek: Don't flush buffers on same offset

  - sftp: statvfs: Along error path, reset the correct
    'state' variable.

  - sftp: Add support for fsync (OpenSSH extension).

  - _libssh2_channel_read: fix data drop when out of window

  - comp_method_zlib_decomp: Improve buffer growing
    algorithm

  - _libssh2_channel_read: Honour window_size_initial

  - window_size: redid window handling for flow control
    reasons

  - knownhosts: handle unknown key types"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=921070"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libssh2_org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssh2-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssh2-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssh2-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssh2-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssh2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssh2_org-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"libssh2-1-1.5.0-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libssh2-1-debuginfo-1.5.0-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libssh2-devel-1.5.0-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libssh2_org-debugsource-1.5.0-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libssh2-1-32bit-1.5.0-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libssh2-1-debuginfo-32bit-1.5.0-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssh2-1-1.5.0-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssh2-1-debuginfo-1.5.0-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssh2-devel-1.5.0-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssh2_org-debugsource-1.5.0-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libssh2-1-32bit-1.5.0-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libssh2-1-debuginfo-32bit-1.5.0-9.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssh2-1 / libssh2-1-32bit / libssh2-1-debuginfo / etc");
}
