#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-482.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77126);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/08/12 14:41:11 $");

  script_cve_id("CVE-2011-1407", "CVE-2012-5671", "CVE-2014-2957", "CVE-2014-2972");

  script_name(english:"openSUSE Security Update : exim (openSUSE-SU-2014:0983-1)");
  script_summary(english:"Check for the openSUSE-2014-482 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in exim :

  - Silence static checkers; (beo#1506).

  - update to 4.83 This release of Exim includes one
    incompatible fix :

  + the behavior of expansion of arguments to math
    comparison functions (<, <=, =, =>, >) was unexpected,
    expanding the values twice; CVE-2014-2972; (bnc#888520)
    This release contains the following enhancements and
    bugfixes :

  + PRDR was promoted from Experimental to mainline

  + OCSP Stapling was promoted from Experimental to mainline

  + new Experimental feature Proxy Protocol

  + new Experimental feature DSN (Delivery Status
    Notifications)

  + TLS session improvements

  + TLS SNI fixes

  + LDAP enhancements

  + DMARC fixes (previous CVE-2014-2957) and new
    $dmarc_domain_policy

  + several new operations (listextract, utf8clean, md5,
    sha1)

  + enforce header formatting with verify=header_names_ascii

  + new commandline option -oMm

  + new TLSA dns lookup

  + new malware 'sock' type

  + cutthrough routing enhancements

  + logging enhancements

  + DNSSEC enhancements

  + exiqgrep enhancements

  + deprecating non-standard SPF results

  + build and portability fixes

  + documentation fixes and enhancements

  - Verify source tar ball gpg signature.

  - Refresh exim-enable_ecdh_openssl.patch and strip version
    number from the patch filename.

  - exim482-enable_ecdh_openssl.patch: Enable ECDH (elliptic
    curve diffie hellman) support, taken from
    http://bugs.exim.org/show_bug.cgi?id=1397

  - BuildRequire libopenssl-devel only on SUSE systems.

  - Fix suse_version condition of the pre- and postun
    scriptlets.

  - Call service_add_pre from pre scriptlet on post-12.2
    systems.

  - update to 4.82

  - Add -bI: framework, and -bI:sieve for querying sieve
    capabilities.

  - Make -n do something, by making it not do something.
    When combined with -bP, the name of an option is not
    output.

  - Added tls_dh_min_bits SMTP transport driver option, only
    honoured by GnuTLS.

  - First step towards DNSSEC, provide $sender_host_dnssec
    for $sender_host_name and config options to manage this,
    and basic check routines.

  - DSCP support for outbound connections and control
    modifier for inbound.

  - Cyrus SASL: set local and remote IP;port properties for
    driver. (Only plugin which currently uses this is
    kerberos4, which nobody should be using, but we should
    make it available and other future plugins might
    conceivably use it, even though it would break NAT;
    stuff *should* be using channel bindings instead).

  - Handle 'exim -L <tag>' to indicate to use syslog with
    tag as the process name; added for Sendmail
    compatibility; requires admin caller. Handle -G as
    equivalent to 'control = suppress_local_fixups' (we used
    to just ignore it); requires trusted caller. Also parse
    but ignore: -Ac -Am -X<logfile> Bugzilla 1117.

  - Bugzilla 1258 - Refactor MAIL FROM optional args
    processing.

  - Add +smtp_confirmation as a default logging option.

  - Bugzilla 198 - Implement remove_header ACL modifier.

  - Bugzilla 1197, 1281, 1283 - Spec typo.

  - Bugzilla 1290 - Spec grammar fixes.

  - Bugzilla 1285 - Spec omission, fix docbook errors for
    spec.txt creation.

  - Add Experimental DMARC support using libopendmarc
    libraries.

  - Fix an out of order global option causing a segfault.
    Reported to dev mailing list by by Dmitry Isaikin.

  - Bugzilla 1201 & 304 - New cutthrough-delivery feature,
    with TLS support.

  - Support 'G' suffix to numbers in ${if comparisons.

  - Handle smtp transport tls_sni option forced-fail for
    OpenSSL.

  - Bugzilla 1196 - Spec examples corrections

  - Add expansion operators ${listnamed:name} and
    ${listcount:string}

  - Add gnutls_allow_auto_pkcs11 option (was originally
    called gnutls_enable_pkcs11, but renamed to more
    accurately indicate its function.

  - Let Linux makefile inherit CFLAGS/CFLAGS_DYNAMIC. Pulled
    from Debian 30_dontoverridecflags.dpatch by Andreas
    Metzler.

  - Add expansion item ${acl {name}{arg}...}, expansion
    condition 'acl {{name}{arg}...}', and optional args on
    acl condition 'acl = name arg...'

  - Permit multiple router/transport headers_add/remove
    lines.

  - Add dnsdb pseudo-lookup 'a+' to do an 'aaaa' + 'a'
    combination.

  - Avoid using a waiting database for a single-message-only
    transport. Performance patch from Paul Fisher. Bugzilla
    1262.

  - Strip leading/trailing newlines from add_header ACL
    modifier data. Bugzilla 884.

  - Add $headers_added variable, with content from use of
    ACL modifier add_header (but not yet added to the
    message). Bugzilla 199.

  - Add 8bitmime log_selector, for 8bitmime status on the
    received line. Pulled from Bugzilla 817 by Wolfgang
    Breyha.

  - SECURITY: protect DKIM DNS decoding from remote exploit.
    CVE-2012-5671 (nb: this is the same fix as in Exim
    4.80.1)

  - Add A= logging on delivery lines, and a client_set_id
    option on authenticators.

  - Add optional authenticated_sender logging to A= and a
    log_selector for control.

  - Unbreak server_set_id for NTLM/SPA auth, broken by 4.80
    PP/29.

  - Dovecot auth: log better reason to rejectlog if Dovecot
    did not advertise SMTP AUTH mechanism to us, instead of
    a generic protocol violation error. Also, make Exim more
    robust to bad data from the Dovecot auth socket.

  - Fix ultimate retry timeouts for intermittently
    deliverable recipients.

  - When a queue runner is handling a message, Exim first
    routes the recipient addresses, during which it prunes
    them based on the retry hints database. After that it
    attempts to deliver the message to any remaining
    recipients. It then updates the hints database using the
    retry rules.

  - So if a recipient address works intermittently, it can
    get repeatedly deferred at routing time. The retry hints
    record remains fresh so the address never reaches the
    final cutoff time.

  - This is a fairly common occurrence when a user is
    bumping up against their storage quota. Exim had some
    logic in its local delivery code to deal with this.
    However it did not apply to per-recipient defers in
    remote deliveries, e.g. over LMTP to a separate IMAP
    message store.

  - This change adds a proper retry rule check during
    routing so that the final cutoff time is checked against
    the message's age. We only do this check if there is an
    address retry record and there is not a domain retry
    record; this implies that previous attempts to handle
    the address had the retry_use_local_parts option turned
    on. We use this as an approximation for the destination
    being like a local delivery, as in LMTP.

  - I suspect this new check makes the old local delivery
    cutoff check redundant, but I have not verified this so
    I left the code in place.

  - Correct gecos expansion when From: is a prefix of the
    username.

  - Test 0254 submits a message to Exim with the header &#9;
    Resent-From: f

  - When I ran the test suite under the user fanf2, Exim
    expanded the header to contain my full name, whereas it
    should have added a Resent-Sender: header. It
    erroneously treats any prefix of the username as equal
    to the username. This change corrects that bug.

  - DCC debug and logging tidyup Error conditions log to
    paniclog rather than rejectlog. Debug lines prefixed by
    'DCC: ' to remove any ambiguity.

  - Avoid unnecessary rebuilds of lookup-related code.

  - Fix OCSP reinitialisation in SNI handling for Exim/TLS
    as server. Bug spotted by Jeremy Harris; was flawed
    since initial commit. Would have resulted in OCSP
    responses post-SNI triggering an Exim NULL dereference
    and crash.

  - Add $router_name and $transport_name variables. Bugzilla
    308.

  - Define SIOCGIFCONF_GIVES_ADDR for GNU Hurd. Bug
    detection, analysis and fix by Samuel Thibault. Bugzilla
    1331, Debian bug #698092.

  - Update eximstats to watch out for senders sending 'HELO
    [IpAddr]'

  - SMTP PRDR
    (http://www.eric-a-hall.com/specs/draft-hall-prdr-00.txt
    ). Server implementation by Todd Lyons, client by JH.
    Only enabled when compiled with EXPERIMENTAL_PRDR. A new
    config variable 'prdr_enable' controls whether the
    server advertises the facility. If the client requests
    PRDR a new acl_data_smtp_prdr ACL is called once for
    each recipient, after the body content is received and
    before the acl_smtp_data ACL. The client is controlled
    by bolth of: a hosts_try_prdr option on the smtp
    transport, and the server advertisement. Default client
    logging of deliveries and rejections involving PRDR are
    flagged with the string 'PRDR'.

  - Fix problems caused by timeouts during quit ACLs trying
    to double fclose(). Diagnosis by Todd Lyons. Update
    configure.default to handle IPv6 localhost better. Patch
    by Alain Williams (plus minor tweaks). Bugzilla 880.

  - OpenSSL made graceful with empty tls_verify_certificates
    setting. This is now consistent with GnuTLS, and is now
    documented: the previous undocumented portable approach
    to treating the option as unset was to force an
    expansion failure. That still works, and an empty string
    is now equivalent.

  - Renamed DNSSEC-enabling option to 'dns_dnssec_ok', to
    make it clearer that Exim is using the DO (DNSSEC OK)
    EDNS0 resolver flag, not performing validation itself.

  - Added force_command boolean option to pipe transport.
    Patch from Nick Koston, of cPanel Inc.

  - AUTH support on callouts (and hence
    cutthrough-deliveries). Bugzilla 321, 823.

  - Added udpsend ACL modifer and hexquote expansion
    operator

  - Fix eximon continuous updating with timestamped
    log-files. Broken in a format-string cleanup in 4.80,
    missed when I repaired the other false fix of the same
    issue. Report and fix from Heiko Schlichting. Bugzilla
    1363.

  - Guard LDAP TLS usage against Solaris LDAP variant.
    Report from Prashanth Katuri.

  - Support safari_ecdhe_ecdsa_bug for openssl_options. It's
    SecureTransport, so affects any MacOS clients which use
    the system-integrated TLS libraries, including email
    clients.

  - Fix segfault from trying to fprintf() to a NULL stdio
    FILE* if using a MIME ACL for non-SMTP local injection.
    Report and assistance in diagnosis by Warren Baker.

  - Adjust exiqgrep to be case-insensitive for
    sender/receiver.

  - Fix comparisons for 64b. Bugzilla 1385.

  - Add expansion variable $authenticated_fail_id to keep
    track of last id that failed so it may be referenced in
    subsequent ACL's.

  - Bugzilla 1375 - Prevent TLS rebinding in ldap. Patch
    provided by Alexander Miroch.

  - Bugzilla 1382 - Option ldap_require_cert overrides
    start_tls ldap library initialization, allowing
    self-signed CA's to be used. Also properly sets
    require_cert option later in code by using NULL (global
    ldap config) instead of ldap handle (per session). Bug
    diagnosis and testing by alxgomz.

  - Enhanced documentation in the ratelimit.pl script
    provided in the src/util/ subdirectory.

  - Bug 1301 - Imported transport SQL logging patch from
    Axel Rau renamed to Transport Post Delivery Action by
    Jeremy Harris, as EXPERIMENTAL_TPDA.

  - Bugzilla 1217 - Redis lookup support has been added. It
    is only enabled when Exim is compiled with
    EXPERIMENTAL_REDIS. A new config variable redis_servers
    = needs to be configured which will be used by the redis
    lookup. Patch from Warren Baker, of The Packet Hub.

  - Fix exiqsumm summary for corner case. Patch provided by
    Richard Hall.

  - Bugzilla 1289 - Clarify host/ip processing when have
    errors looking up a hostname or reverse DNS when
    processing a host list. Used suggestions from multiple
    comments on this bug.

  - Bugzilla 1057 - Multiple clamd TCP targets patch from
    Mark Zealey.

  - Had previously added a -CONTINUE option to runtest in
    the test suite. Missed a few lines, added it to make the
    runtest require no keyboard interaction.

  - Bugzilla 1402 - Test 533 fails if any part of the path
    to the test suite contains upper case chars. Make router
    use caseful_local_part.

  - Bugzilla 1400 - Add AVOID_GNUTLS_PKCS11 build option.
    Allows GnuTLS support when GnuTLS has been built with
    p11-kit.

  - Add systemd support for openSUSE > 12.2

  - Remove some obsolete conditionnal macros

  - exim.spec forces the use of SSL libraries, so make sure
    the BuildRequires are there. Also add previously
    implicit cyrus-sasl back.

  - Fixed another remote code execution issue (CVE-2011-1407
    / bnc#694798)

  - Fixed STARTTLS command injection (bnc#695144)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.exim.org/show_bug.cgi?id=1397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-08/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.eric-a-hall.com/specs/draft-hall-prdr-00.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=694798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=695144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=888520"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected exim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exim-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eximon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eximon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eximstats-html");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"exim-4.83-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"exim-debuginfo-4.83-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"exim-debugsource-4.83-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"eximon-4.83-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"eximon-debuginfo-4.83-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"eximstats-html-4.83-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"exim-4.83-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"exim-debuginfo-4.83-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"exim-debugsource-4.83-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"eximon-4.83-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"eximon-debuginfo-4.83-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"eximstats-html-4.83-6.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim / exim-debuginfo / exim-debugsource / eximon / etc");
}
