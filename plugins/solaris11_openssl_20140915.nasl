#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80722);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3512", "CVE-2014-5139");

  script_name(english:"Oracle Solaris Third-Party Patch Update : openssl (cve_2014_3505_denial_of)");
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

  - Double free vulnerability in d1_both.c in the DTLS
    implementation in OpenSSL 0.9.8 before 0.9.8zb, 1.0.0
    before 1.0.0n, and 1.0.1 before 1.0.1i allows remote
    attackers to cause a denial of service (application
    crash) via crafted DTLS packets that trigger an error
    condition. (CVE-2014-3505)

  - d1_both.c in the DTLS implementation in OpenSSL 0.9.8
    before 0.9.8zb, 1.0.0 before 1.0.0n, and 1.0.1 before
    1.0.1i allows remote attackers to cause a denial of
    service (memory consumption) via crafted DTLS handshake
    messages that trigger memory allocations corresponding
    to large length values. (CVE-2014-3506)

  - Memory leak in d1_both.c in the DTLS implementation in
    OpenSSL 0.9.8 before 0.9.8zb, 1.0.0 before 1.0.0n, and
    1.0.1 before 1.0.1i allows remote attackers to cause a
    denial of service (memory consumption) via zero-length
    DTLS fragments that trigger improper handling of the
    return value of a certain insert function.
    (CVE-2014-3507)

  - Race condition in the ssl_parse_serverhello_tlsext
    function in t1_lib.c in OpenSSL 1.0.0 before 1.0.0n and
    1.0.1 before 1.0.1i, when multithreading and session
    resumption are used, allows remote SSL servers to cause
    a denial of service (memory overwrite and client
    application crash) or possibly have unspecified other
    impact by sending Elliptic Curve (EC) Supported Point
    Formats Extension data. (CVE-2014-3509)

  - The ssl3_send_client_key_exchange function in s3_clnt.c
    in OpenSSL 0.9.8 before 0.9.8zb, 1.0.0 before 1.0.0n,
    and 1.0.1 before 1.0.1i allows remote DTLS servers to
    cause a denial of service (NULL pointer dereference and
    client application crash) via a crafted handshake
    message in conjunction with a (1) anonymous DH or (2)
    anonymous ECDH ciphersuite. (CVE-2014-3510)

  - Multiple buffer overflows in crypto/srp/srp_lib.c in the
    SRP implementation in OpenSSL 1.0.1 before 1.0.1i allow
    remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via an invalid SRP (1) g, (2) A, or (3) B
    parameter. (CVE-2014-3512)

  - The ssl_set_client_disabled function in t1_lib.c in
    OpenSSL 1.0.1 before 1.0.1i allows remote SSL servers to
    cause a denial of service (NULL pointer dereference and
    client application crash) via a ServerHello message that
    includes an SRP ciphersuite without the required
    negotiation of that ciphersuite with the client.
    (CVE-2014-5139)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2014_3505_denial_of"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2014_3506_resource_management
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7496e7be"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2014_3507_resource_management
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6958400a"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2014_3509_race_conditions
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ee3306c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2014_3510_denial_of"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2014_3512_buffer_errors"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2014_5139_denial_of"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.2.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:openssl");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/15");
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

if (solaris_check_release(release:"0.5.11-0.175.2.2.0.5.0", sru:"SRU 11.2.2.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : openssl\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "openssl");
