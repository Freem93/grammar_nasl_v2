#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80720);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2010-5298", "CVE-2013-4353", "CVE-2013-6449", "CVE-2013-6450", "CVE-2014-0076", "CVE-2014-0195", "CVE-2014-0198", "CVE-2014-0221", "CVE-2014-3470");

  script_name(english:"Oracle Solaris Third-Party Patch Update : openssl (cve_2010_5298_race_conditions)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - Race condition in the ssl3_read_bytes function in
    s3_pkt.c in OpenSSL through 1.0.1g, when
    SSL_MODE_RELEASE_BUFFERS is enabled, allows remote
    attackers to inject data across sessions or cause a
    denial of service (use-after-free and parsing error) via
    an SSL connection in a multithreaded environment.
    (CVE-2010-5298)

  - The ssl3_take_mac function in ssl/s3_both.c in OpenSSL
    1.0.1 before 1.0.1f allows remote TLS servers to cause a
    denial of service (NULL pointer dereference and
    application crash) via a crafted Next Protocol
    Negotiation record in a TLS handshake. (CVE-2013-4353)

  - The ssl_get_algorithm2 function in ssl/s3_lib.c in
    OpenSSL before 1.0.2 obtains a certain version number
    from an incorrect data structure, which allows remote
    attackers to cause a denial of service (daemon crash)
    via crafted traffic from a TLS 1.2 client.
    (CVE-2013-6449)

  - The DTLS retransmission implementation in OpenSSL 1.0.0
    before 1.0.0l and 1.0.1 before 1.0.1f does not properly
    maintain data structures for digest and encryption
    contexts, which might allow man-in-the-middle attackers
    to trigger the use of a different context and cause a
    denial of service (application crash) by interfering
    with packet delivery, related to ssl/d1_both.c and ssl/
    t1_enc.c. (CVE-2013-6450)

  - The Montgomery ladder implementation in OpenSSL through
    1.0.0l does not ensure that certain swap operations have
    a constant-time behavior, which makes it easier for
    local users to obtain ECDSA nonces via a FLUSH+RELOAD
    cache side-channel attack. (CVE-2014-0076)

  - The dtls1_reassemble_fragment function in d1_both.c in
    OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1
    before 1.0.1h does not properly validate fragment
    lengths in DTLS ClientHello messages, which allows
    remote attackers to execute arbitrary code or cause a
    denial of service (buffer overflow and application
    crash) via a long non-initial fragment. (CVE-2014-0195)

  - The do_ssl3_write function in s3_pkt.c in OpenSSL 1.x
    through 1.0.1g, when SSL_MODE_RELEASE_BUFFERS is
    enabled, does not properly manage a buffer pointer
    during certain recursive calls, which allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via vectors that
    trigger an alert condition. (CVE-2014-0198)

  - The dtls1_get_message_fragment function in d1_both.c in
    OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1
    before 1.0.1h allows remote attackers to cause a denial
    of service (recursion and client crash) via a DTLS hello
    message in an invalid DTLS handshake. (CVE-2014-0221)

  - The ssl3_send_client_key_exchange function in s3_clnt.c
    in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and
    1.0.1 before 1.0.1h, when an anonymous ECDH cipher suite
    is used, allows remote attackers to cause a denial of
    service (NULL pointer dereference and client crash) by
    triggering a NULL certificate value. (CVE-2014-3470)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2010_5298_race_conditions
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec97a688"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2014_0076_cryptographic_issues
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55c93ba5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2014_0195_buffer_errors"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2014_0198_buffer_errors"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2014_0221_resource_management
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18770424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2014_3470_denial_of"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_openssl3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df4641c9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.20.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:openssl");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^openssl$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.20.0.5.0", sru:"SRU 11.1.20.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : openssl\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "openssl");
