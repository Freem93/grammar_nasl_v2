#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-387.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90165);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2016-3116");

  script_name(english:"openSUSE Security Update : dropbear (openSUSE-2016-387)");
  script_summary(english:"Check for the openSUSE-2016-387 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"dropbear was updated to 2016.72 to fix the following issues :

Changes in dropbear :

  - updated to upstream version 2016.72

  - Validate X11 forwarding input. Could allow bypass of
    authorized_keys command= restrictions, found by
    github.com/tintinweb. Thanks for Damien Miller for a
    patch.

  - used as bug fix release for boo#970633 - CVE-2016-3116

  - updated to upstream version 2015.71

  - Fix 'bad buf_incrpos' when data is transferred, broke in
    2015.69

  - Fix crash on exit when -p address:port is used, broke in
    2015.68

  - Fix building with only ENABLE_CLI_REMOTETCPFWD given,
    patch from Konstantin Tokarev

  - Fix bad configure script test which didn't work with
    dash shell, patch from Juergen Daubert, broke in 2015.70

  - Fix server race condition that could cause sessions to
    hang on exit,
    https://github.com/robotframework/SSHLibrary/issues/128

  - updated to upstream version 2015.70

  - Fix server password authentication on Linux, broke in
    2015.69

  - Fix crash when forwarded TCP connections fail to connect
    (bug introduced in 2015.68)

  - Avoid hang on session close when multiple sessions are
    started, affects Qt Creator Patch from Andrzej
    Szombierski

  - Reduce per-channel memory consumption in common case,
    increase default channel limit from 100 to 1000 which
    should improve SOCKS forwarding for modern webpages

  - Handle multiple command line arguments in a single flag,
    thanks to Guilhem Moulin

  - Manpage improvements from Guilhem Moulin

  - Build fixes for Android from Mike Frysinger

  - Don't display the MOTD when an explicit command is run
    from Guilhem Moulin

  - Check curve25519 shared secret isn't zero

  - updated to upstream version 2015.68

  - Reduce local data copying for improved efficiency.
    Measured 30% increase in throughput for connections to
    localhost

  - Forwarded TCP ports connect asynchronously and try all
    available addresses (IPv4, IPv6, round robin DNS)

  - Fix all compile warnings, many patches from Ga&euml;l
    Portay Note that configure with -Werror may not be
    successful on some platforms (OS X) and some
    configuration options may still result in unused
    variable warnings.

  - Use TCP Fast Open on Linux if available. Saves a round
    trip at connection to hosts that have previously been
    connected. Needs a recent Linux kernel and possibly
    'sysctl -w net.ipv4.tcp_fastopen=3' Client side is
    disabled by default pending further compatibility
    testing with networks and systems.

  - Increase maximum command length to 9000 bytes

  - Free memory before exiting, patch from Thorsten
    Horstmann. Useful for Dropbear ports to embedded systems
    and for checking memory leaks with valgrind. Only
    partially implemented for dbclient. This is disabled by
    default, enable with DROPBEAR_CLEANUP in sysoptions.h

  - DROPBEAR_DEFAULT_CLI_AUTHKEY setting now always prepends
    home directory unless there is a leading slash (~ isn't
    treated specially)

  - Fix small ECC memory leaks

  - Tighten validation of Diffie-Hellman parameters, from
    Florent Daigniere of Matta Consulting. Odds of bad
    values are around 2**-512 -- improbable.

  - Twofish-ctr cipher is supported though disabled by
    default

  - Fix pre-authentication timeout when waiting for client
    SSH-2.0 banner, thanks to CL Ouyang

  - Fix NULL pointer crash with restrictions in
    authorized_keys without a command, patch from Guilhem
    Moulin

  - Ensure authentication timeout is handled while reading
    the initial banner, thanks to CL Ouyang for finding it.

  - Fix NULL pointer crash when handling bad ECC keys. Found
    by afl-fuzz

  - fixed checksum URL

  - updated to upstream version 2015.67

  - Call fsync() after generating private keys to ensure
    they aren't lost if a reboot occurs. Thanks to Peter
    Korsgaard

  - Disable non-delayed zlib compression by default on the
    server. Can be enabled if required for old clients with
    DROPBEAR_SERVER_DELAY_ZLIB

  - Default client key path ~/.ssh/id_dropbear

  - Prefer stronger algorithms by default, from Fedor
    Brunner. AES256 over 3DES Diffie-hellman group14 over
    group1

  - Add option to disable CBC ciphers.

  - Disable twofish in default options.h

  - Enable sha2 HMAC algorithms by default, the code was
    already required for ECC key exchange. sha1 is the first
    preference still for performance. 

  - Fix installing dropbear.8 in a separate build directory,
    from Like Ma

  - Allow configure to succeed if libtomcrypt/libtommath are
    missing, from Elan Ruusam&auml;e

  - Don't crash if ssh-agent provides an unknown type of
    key. From Catalin Patulea

  - Minor bug fixes, a few issues found by Coverity scan 

  - replaced deprecated gpg-offline check by
    obs-service-source_validator

  - updated to upstream version 2014.66

  - Use the same keepalive handling behaviour as OpenSSH.
    This will work better with some SSH implementations that
    have different behaviour with unknown message types.

  - Don't reply with SSH_MSG_UNIMPLEMENTED when we receive a
    reply to our own keepalive message

  - Set $SSH_CLIENT to keep bash happy, patch from Ryan
    Cleere

  - Fix wtmp which broke since 2013.62, patch from Whoopie"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/robotframework/SSHLibrary/issues/128"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dropbear packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dropbear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dropbear-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dropbear-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"dropbear-2016.72-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dropbear-debuginfo-2016.72-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dropbear-debugsource-2016.72-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dropbear-2016.72-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dropbear-debuginfo-2016.72-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dropbear-debugsource-2016.72-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dropbear / dropbear-debuginfo / dropbear-debugsource");
}
