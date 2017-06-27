#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-898.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87394);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/16 15:10:33 $");

  script_cve_id("CVE-2015-5291");

  script_name(english:"openSUSE Security Update : mbedtls (openSUSE-2015-898)");
  script_summary(english:"Check for the openSUSE-2015-898 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mbedtls fixes the following security and non-security
issues :

  - Update to 1.3.15

  - Fix potential double free if ssl_set_psk() is called
    more than once and some allocation fails. Cannot be
    forced remotely. Found by Guido Vranken, Intelworks.

  - Fix potential heap corruption on windows when
    x509_crt_parse_path() is passed a path longer than 2GB.
    Cannot be triggered remotely. Found by Guido Vranken,
    Intelworks.

  - Fix potential buffer overflow in some asn1_write_xxx()
    functions. Cannot be triggered remotely unless you
    create X.509 certificates based on untrusted input or
    write keys of untrusted origin. Found by Guido Vranken,
    Intelworks.

  - The x509 max_pathlen constraint was not enforced on
    intermediate certificates. Found by Nicholas Wilson, fix
    and tests provided by Janos Follath. #280 and #319

  - Self-signed certificates were not excluded from pathlen
    counting, resulting in some valid X.509 being
    incorrectly rejected. Found and fix provided by Janos
    Follath. #319

  - Fix bug causing some handshakes to fail due to some
    non-fatal alerts not begin properly ignored. Found by
    mancha and Kasom Koht-arsa, #308

  - Fix build error with configurations where ecdhe-psk is
    the only key exchange. Found and fix provided by Chris
    Hammond. #270

  - Fix failures in mpi on sparc(64) due to use of bad
    assembly code. Found by Kurt Danielson. #292

  - Fix typo in name of the extkeyusage oid. found by
    inestlerode, #314

  - Fix bug in asn.1 encoding of booleans that caused
    generated ca certificates to be rejected by some
    applications, including OS X Keychain. Found and fixed
    by Jonathan Leroy, Inikup.

  - Fix 'destination buffer is too small' error in
    cert_write program. Found and fixed by Jonathan Leroy,
    Inikup.

  - Update to 1.3.14

  - Added fix for CVE-2015-5291 (boo#949380) to prevent heap
    corruption due to buffer overflow of the hostname or
    session ticket. Found by Guido Vranken, Intelworks.

  - Fix stack-based buffer overflow in pkcs12 decryption
    (used by mbedtls_pk_parse_key(file)() when the password
    is > 129 bytes. Found by Guido Vranken, Intelworks. Not
    triggerable remotely.

  - Fix potential buffer overflow in
    mbedtls_mpi_read_string(). Found by Guido Vranken,
    Intelworks. Not exploitable remotely in the context of
    TLS, but might be in other uses. On 32 bit machines,
    requires reading a string of close to or larger than 1GB
    to exploit; on 64 bit machines, would require reading a
    string of close to or larger than 2^62 bytes.

  - Fix potential random memory allocation in
    mbedtls_pem_read_buffer() on crafted PEM input data.
    Found and fix provided by Guido Vranken, Intelworks. Not
    triggerable remotely in TLS. Triggerable remotely if you
    accept PEM data from an untrusted source.

  - Fix potential double-free if ssl_set_psk() is called
    repeatedly on the same ssl_context object and some
    memory allocations fail. Found by Guido Vranken,
    Intelworks. Can not be forced remotely.

  - Fix possible heap buffer overflow in base64_encode()
    when the input buffer is 512MB or larger on 32-bit
    platforms. Found by Guido Vranken, Intelworks. Found by
    Guido Vranken. Not trigerrable remotely in TLS.

  - Fix potential heap buffer overflow in servers that
    perform client authentication against a crafted CA cert.
    Cannot be triggered remotely unless you allow third
    parties to pick trust CAs for client auth. Found by
    Guido Vranken, Intelworks.

  - Fix compile error in net.c with musl libc. found and
    patch provided by zhasha (#278).

  - Fix macroization of 'inline' keywork when building as
    c++. (#279)

  - Added checking of hostname length in ssl_set_hostname()
    to ensure domain names are compliant with RFC 1035.

  - Changes for 1.3.13

  - Fix possible client-side NULL pointer dereference (read)
    when the client tries to continue the handshake after it
    failed (a misuse of the API). (Found and patch provided
    by Fabian Foerg, Gotham Digital Science using afl-fuzz.)

  - Add countermeasure against lenstra's rsa-crt attack for
    pkcs#1 v1.5 signatures. (Found by Florian Weimer, Red
    Hat.)
    https://securityblog.redhat.com/2015/09/02/factoring-rsa
    -keys-with-tls-perfect-forward-secrecy/

  - Setting ssl_min_dhm_bytes in config.h had no effect
    (overriden in ssl.h) (found by Fabio Solari) (#256)

  - Fix bug in mbedtls_rsa_public() and
    mbedtls_rsa_private() that could result trying to unlock
    an unlocked mutex on invalid input (found by Fredrik
    Axelsson) (#257)

  - Fix -wshadow warnings (found by hnrkp) (#240)

  - Fix unused function warning when using mbedtls_mdx_alt
    or MBEDTLS_SHAxxx_ALT (found by Henrik) (#239)

  - Fix memory corruption in pkey programs (found by
    yankuncheng) (#210)

  - Fix memory corruption on client with overlong psk
    identity, around SSL_MAX_CONTENT_LEN or higher - not
    triggerrable remotely (found by Aleksandrs Saveljevs)
    (#238)

  - Fix off-by-one error in parsing supported point format
    extension that caused some handshakes to fail.

  - When verifying a certificate chain, if an intermediate
    certificate is trusted, no later cert is checked.
    (suggested by hannes-landeholm) (#220).

  - Changes for 1.3.12

  - Increase the minimum size of diffie-hellman parameters
    accepted by the client to 1024 bits, to protect against
    Logjam attack.

  - Increase the size of default diffie-hellman parameters
    on the server to 2048 bits. This can be changed with
    ssl_set_dh_params().

  - Fix thread-safety issue in ssl debug module (found by
    edwin van vliet).

  - Some example programs were not built using make, not
    included in visual Studio projects (found by Kristian
    Bendiksen).

  - Fix build error with cmake and pre-4.5 versions of gcc
    (found by hugo Leisink).

  - Fix missing -static-ligcc when building shared libraries
    for windows with make.

  - Fix compile error with armcc5 --gnu.

  - Add ssl_min_dhm_bytes configuration parameter in
    config.h to choose the minimum size of Diffie-Hellman
    parameters accepted by the client.

  - The pem parser now accepts a trailing space at end of
    lines (#226)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949380"
  );
  # https://securityblog.redhat.com/2015/09/02/factoring-rsa-keys-with-tls-perfect-forward-secrecy/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1795184d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mbedtls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmbedtls9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmbedtls9-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmbedtls9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmbedtls9-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mbedtls-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mbedtls-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libmbedtls9-1.3.15-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmbedtls9-debuginfo-1.3.15-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mbedtls-debugsource-1.3.15-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mbedtls-devel-1.3.15-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmbedtls9-32bit-1.3.15-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmbedtls9-debuginfo-32bit-1.3.15-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmbedtls9 / libmbedtls9-32bit / libmbedtls9-debuginfo / etc");
}
