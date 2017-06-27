#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-10691.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(35227);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:04:04 $");

  script_bugtraq_id(30532);
  script_xref(name:"FEDORA", value:"2008-10691");

  script_name(english:"Fedora 9 : openvpn-2.1-0.29.rc15.fc9 (2008-10691)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"2008.11.19 -- Version 2.1_rc15 * Fixed issue introduced in 2.1_rc14
that may cause a segfault when a --plugin module is used. * Added
server-side --opt-verify option: clients that connect with options
that are incompatible with those of the server will be disconnected
(without this option, incompatible clients would trigger a warning
message in the server log but would not be disconnected). * Added
--tcp-nodelay option: Macro that sets TCP_NODELAY socket flag on the
server as well as pushes it to connecting clients. * Minor options
check fix: --no-name-remapping is a server-only option and should
therefore generate an error when used on the client. * Added --prng
option to control PRNG (pseudo-random number generator) parameters. In
previous OpenVPN versions, the PRNG was hard-coded to use the SHA1
hash. Now any OpenSSL hash may be used. This is part of an effort to
remove hard-coded references to a specific cipher or cryptographic
hash algorithm. * Cleaned up man page synopsis. 2008.11.16 -- Version
2.1_rc14

  - Added AC_GNU_SOURCE to configure.ac to enable struct
    ucred, with the goal of fixing a build issue on Fedora 9
    that was introduced in 2.1_rc13. * Added additional
    method parameter to --script-security to preserve
    backward compatibility with system() call semantics used
    in OpenVPN 2.1_rc8 and earlier. To preserve backward
    compatibility use: script-security 3 system * Added
    additional warning messages about --script-security 2 or
    higher being required to execute user-defined scripts or
    executables. * Windows build system changes: Modified
    Windows domake-win build system to write all openvpn.nsi
    input files to gen, so that gen can be disconnected from
    the rest of the source tree and makensis openvpn.nsi
    will still function correctly. Added additional
    SAMPCONF_(CA|CRT|KEY) macros to settings.in (commented
    out by default). Added optional files SAMPCONF_CONF2
    (second sample configuration file) and SAMPCONF_DH
    (Diffie- Helman parameters) to Windows build system, and
    may be defined in settings.in. * Extended Management
    Interface 'bytecount' command to work when OpenVPN is
    running as a server. Documented Management Interface
    'bytecount' command in management/management-notes.txt.
    * Fixed informational message in ssl.c to properly
    indicate deferred authentication.

  - Added server-side --auth-user-pass-optional directive,
    to allow connections by clients that do not specify a
    username/password, when a user-defined authentication
    script/module is in place (via --auth-user-pass-verify,
    --management-client-auth, or a plugin module). * Changes
    to easy- rsa/2.0/pkitool and related openssl.cnf:
    Calling scripts can set the KEY_NAME environmental
    variable to set the 'name' X509 subject field in
    generated certificates. Modified pkitool to allow
    flexibility in separating the Common Name convention
    from the cert/key filename convention. For example:
    KEY_CN='James's Laptop' KEY_NAME='james' ./pkitool james
    will create a client certificate/key pair of
    james.crt/james.key having a Common Name of 'James's
    Laptop' and a Name of 'james'. * Added
    --no-name-remapping option to allow Common Name, X509
    Subject, and username strings to include any printable
    character including space, but excluding control
    characters such as tab, newline, and carriage-return
    (this is important for compatibility with external
    authentication systems). As a related change, added
    --status-version 3 format (and 'status 3' in the
    management interface) which uses the version 2 format
    except that tabs are used as delimiters instead of
    commas so that there is no ambiguity when parsing a
    Common Name that contains a comma. Also, save X509
    Subject fields to environment, using the naming
    convention: X509_{cert_depth}_{name}={value} This is to
    avoid ambiguities when parsing out the X509 subject
    string since '/' characters could potentially be used in
    the common name. * Fixed some ifconfig-pool issues that
    precluded it from being combined with --server
    directive. Now, for example, we can configure thusly:
    server 10.8.0.0 255.255.255.0 nopool ifconfig-pool
    10.8.0.2 10.8.0.99 255.255.255.0 to have ifconfig-pool
    manage only a subset of the VPN subnet. * Added config
    file option 'setenv FORWARD_COMPATIBLE 1' to relax
    config file syntax checking to allow directives for
    future OpenVPN versions to be ignored. 2008.10.07 --
    Version 2.1_rc13 * Bundled OpenSSL 0.9.8i with Windows
    installer. * Management interface can now listen on a
    unix domain socket, for example: management /tmp/openvpn
    unix Also added management-client-user and
    management-client-group directives to control which
    processes are allowed to connect to the socket. *
    Copyright change to OpenVPN Technologies, Inc.
    2008.09.23 -- Version 2.1_rc12 * Patched Makefile.am so
    that the new t_cltsrv-down.sh script becomes part of the
    tarball (Matthias Andree). * Fixed --lladdr bug
    introduced in 2.1-rc9 where input validation code was
    incorrectly expecting the lladdr parameter to be an IP
    address when it is actually a MAC address (HoverHell).
    2008.09.14 -- Version 2.1_rc11 * Fixed a bug that can
    cause SSL/TLS negotiations in UDP mode to fail if UDP
    packets are dropped. 2008.09.10 -- Version 2.1_rc10

  - Added '--server-bridge' (without parameters) to enable
    DHCP proxy mode: Configure server mode for ethernet
    bridging using a DHCP-proxy, where clients talk to the
    OpenVPN server-side DHCP server to receive their IP
    address allocation and DNS server addresses. * Added
    '--route-gateway dhcp', to enable the extraction of the
    gateway address from a DHCP negotiation with the OpenVPN
    server-side LAN. * Fixed minor issue with
    --redirect-gateway bypass- dhcp or bypass-dns on
    Windows. If the bypass IP address is 0.0.0.0 or
    255.255.255.255, ignore it. * Warn when ethernet
    bridging that the IP address of the bridge adapter is
    probably not the same address that the LAN adapter was
    set to previously. * When running as a server, warn if
    the LAN network address is the all-popular
    192.168.[0|1].x, since this condition commonly leads to
    subnet conflicts down the road. * Primarily on the
    client, check for subnet conflicts between the local LAN
    and the VPN subnet.

  - Added a 'netmask' parameter to get_default_gateway, to
    return the netmask of the adapter containing the default
    gateway. Only implemented on Windows so far. Other
    platforms will return 255.255.255.0. Currently the
    netmask information is only used to warn about subnet
    conflicts. * Minor fix to cryptoapi.c to not compile
    itself unless USE_CRYPTO and USE_SSL flags are enabled
    (Alon Bar-Lev). * Updated openvpn/t_cltsrv.sh (used by
    'make check') to conform to new --script-security rules.
    Also adds retrying if the addresses are in use (Matthias
    Andree). * Fixed build issue with ./configure
    --disable-socks --disable-http. * Fixed separate compile
    errors in options.c and ntlm.c that occur on strict C
    compilers (such as old versions of gcc) that require
    that C variable declarations occur at the start of a {}
    block, not in the middle. * Workaround bug in OpenSSL
    0.9.6b ASN1_STRING_to_UTF8, which the new implementation
    of extract_x509_field_ssl depends on. * LZO compression
    buffer overflow errors will now invalidate the packet
    rather than trigger a fatal assertion. * Fixed minor
    compile issue in ntlm.c (mid-block declaration). * Added
    --allow-pull-fqdn option which allows client to pull DNS
    names from server (rather than only IP address) for
    --ifconfig, --route, and --route-gateway. OpenVPN
    versions 2.1_rc7 and earlier allowed DNS names for these
    options to be pulled and translated to IP addresses by
    default. Now --allow-pull-fqdn will be explicitly
    required on the client to enable DNS-name-to-IP-address
    translation of pulled options.

  - 2.1_rc8 and earlier did implicit shell expansion on
    script arguments since all scripts were called by
    system(). The security hardening changes made to 2.1_rc9
    no longer use system(), but rather use the safer execve
    or CreateProcess system calls. The security hardening
    also introduced a backward incompatibility with 2.1_rc8
    and earlier in that script parameters were no longer
    shell-expanded, so for example: client-connect 'docc
    CLIENT-CONNECT' would fail to work because execve would
    try to execute a script called 'docc CLIENT-CONNECT'
    instead of 'docc' with 'CLIENT-CONNECT' as the first
    argument. This patch fixes the issue, bringing the
    script argument semantics back to pre 2.1_rc9 behavior
    in order to preserve backward compatibility while still
    using execve or CreateProcess to execute the
    script/executable. * Modified ip_or_dns_addr_safe, which
    validates pulled DNS names, to more closely conform to
    RFC 3696: (1) DNS name length must not exceed 255
    characters (2) DNS name characters must be limited to
    alphanumeric, dash ('-'), and dot ('.') * Fixed bug in
    intra-session TLS key rollover that was introduced with
    deferred authentication features in 2.1_rc8. 2008.07.31
    -- Version 2.1_rc9 * Security Fix -- affects non-
    Windows OpenVPN clients running OpenVPN 2.1-beta14
    through 2.1-rc8 (OpenVPN 2.0.x clients are NOT
    vulnerable nor are any versions of the OpenVPN server
    vulnerable). An OpenVPN client connecting to a malicious
    or compromised server could potentially receive an
    'lladdr' or 'iproute' configuration directive from the
    server which could cause arbitrary code execution on the
    client. A successful attack requires that (a) the client
    has agreed to allow the server to push configuration
    directives to it by including 'pull' or the macro
    'client' in its configuration file, (b) the client
    successfully authenticates the server, (c) the server is
    malicious or has been compromised and is under the
    control of the attacker, and (d) the client is running a
    non-Windows OS. Credit: David Wagner. * Miscellaneous
    defensive programming changes to multiple areas of the
    code. In particular, use of the system() call for
    calling executables such as ifconfig, route, and
    user-defined scripts has been completely revamped in
    favor of execve() on unix and CreateProcess() on
    Windows.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=457667"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017939.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba0a9308"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openvpn package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvpn");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"openvpn-2.1-0.29.rc15.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvpn");
}
