#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97726);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/03/16 14:21:22 $");

  script_cve_id(
    "CVE-2016-0736",
    "CVE-2016-2161",
    "CVE-2016-5387",
    "CVE-2016-7055",
    "CVE-2016-8740",
    "CVE-2016-8743",
    "CVE-2016-9594",
    "CVE-2016-10158",
    "CVE-2016-10159",
    "CVE-2016-10160",
    "CVE-2016-10161",
    "CVE-2016-10167",
    "CVE-2016-1000102",
    "CVE-2016-1000104",
    "CVE-2017-3731",
    "CVE-2017-3732"
);
  script_bugtraq_id(
    91816,
    91822,
    94242,
    94650,
    95076,
    95077,
    95078,
    95094,
    95764,
    95768,
    95774,
    95783,
    95813,
    95814,
    95869
  );
  script_osvdb_id(
    141669,
    147021,
    148143,
    148286,
    148338,
    149054,
    149163,
    149621,
    149623,
    149629,
    149665,
    149666,
    150576,
    151018,
    151020,
    152085,
    152086,
    152087,
    152088
  );
  script_xref(name:"CERT", value:"797896");
  script_xref(name:"IAVA", value:"2017-A-0010");
  script_xref(name:"EDB-ID", value:"40961");

  script_name(english:"Tenable SecurityCenter 5.x < 5.4.3 Multiple Vulnerabilities (TNS-2017-04) (httpoxy)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable SecurityCenter
on the remote host is affected by multiple vulnerabilities :

  - A flaw exists in the mod_session_crypto module due to
    encryption for data and cookies using the configured
    ciphers with possibly either CBC or ECB modes of
    operation (AES256-CBC by default). An unauthenticated,
    remote attacker can exploit this, via a padding oracle
    attack, to decrypt information without knowledge of the
    encryption key, resulting in the disclosure of
    potentially sensitive information. (CVE-2016-0736)

  - A denial of service vulnerability exists in the
    mod_auth_digest module during client entry allocation.
    An unauthenticated, remote attacker can exploit this,
    via specially crafted input, to exhaust shared memory
    resources, resulting in a server crash. (CVE-2016-2161)

  - The Apache HTTP Server is affected by a
    man-in-the-middle vulnerability known as 'httpoxy' due
    to a failure to properly resolve namespace conflicts in
    accordance with RFC 3875 section 4.1.18. The HTTP_PROXY
    environment variable is set based on untrusted user data
    in the 'Proxy' header of HTTP requests. The HTTP_PROXY
    environment variable is used by some web client
    libraries to specify a remote proxy server. An
    unauthenticated, remote attacker can exploit this, via a
    crafted 'Proxy' header in an HTTP request, to redirect
    an application's internal HTTP traffic to an arbitrary
    proxy server where it may be observed or manipulated.
    (CVE-2016-5387, CVE-2016-1000102, CVE-2016-1000104)

  - A carry propagation error exists in the
    Broadwell-specific Montgomery multiplication procedure
    when handling input lengths divisible by but longer than
    256 bits. This can result in transient authentication
    and key negotiation failures or reproducible erroneous
    outcomes of public-key operations with specially crafted
    input. A man-in-the-middle attacker can possibly exploit
    this issue to compromise ECDH key negotiations that
    utilize Brainpool P-512 curves. (CVE-2016-7055)

  - A denial of service vulnerability exists in the
    mod_http2 module due to improper handling of the
    LimitRequestFields directive. An unauthenticated, remote
    attacker can exploit this, via specially crafted
    CONTINUATION frames in an HTTP/2 request, to inject
    unlimited request headers into the server, resulting in
    the exhaustion of memory resources. (CVE-2016-8740)

  - A flaw exists due to improper handling of whitespace
    patterns in user-agent headers. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted user-agent header, to cause the program to
    incorrectly process sequences of requests, resulting in
    interpreting responses incorrectly, polluting the cache,
    or disclosing the content from one request to a second
    downstream user-agent. (CVE-2016-8743)

  - A flaw exits in libcurl in the randit() function within
    file lib/rand.c due to improper initialization of the
    32-bit random value, which is used, for example, to
    generate Digest and NTLM authentication nonces,
    resulting in weaker cryptographic operations than
    expected. (CVE-2016-9594)

  - A floating pointer exception flaw exists in the
    exif_convert_any_to_int() function in exif.c that is
    triggered when handling TIFF and JPEG image tags. An
    unauthenticated, remote attacker can exploit this to
    cause a crash, resulting in a denial of service
    condition. (CVE-2016-10158)

  - An integer overflow condition exists in the
    phar_parse_pharfile() function in phar.c due to improper
    validation when handling phar archives. An
    unauthenticated, remote attacker can exploit this to
    cause a crash, resulting in a denial of service
    condition. (CVE-2016-10159)

  - An off-by-one overflow condition exists in the
    phar_parse_pharfile() function in phar.c due to improper
    parsing of phar archives. An unauthenticated, remote
    attacker can exploit this to cause a crash, resulting in
    a denial of service condition. (CVE-2016-10160)

  - An out-of-bounds read error exists in the
    finish_nested_data() function in var_unserializer.c due
    to improper validation of unserialized data. An
    unauthenticated, remote attacker can exploit this to
    cause a crash, resulting in a denial of service
    condition or the disclosure of memory contents.
    (CVE-2016-10161)

  - A denial of service vulnerability exists in the
    gdImageCreateFromGd2Ctx() function within file gd_gd2.c
    in the GD Graphics Library (LibGD) when handling images
    claiming to contain more image data than they actually
    do. An unauthenticated, remote attacker can exploit this
    to crash a process linked against the library.
    (CVE-2016-10167)

  - An out-of-bounds read error exists when handling packets
    using the CHACHA20/POLY1305 or RC4-MD5 ciphers. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted truncated packets, to cause a denial
    of service condition. (CVE-2017-3731)

  - A carry propagating error exists in the x86_64
    Montgomery squaring implementation that may cause the
    BN_mod_exp() function to produce incorrect results. An
    unauthenticated, remote attacker with sufficient
    resources can exploit this to obtain sensitive
    information regarding private keys. Note that this issue
    is very similar to CVE-2015-3193. Moreover, the attacker
    would additionally need online access to an unpatched
    system using the target private key in a scenario with
    persistent DH parameters and a private key that is
    shared between multiple clients. For example, this can
    occur by default in OpenSSL DHE based SSL/TLS cipher
    suites. (CVE-2017-3732)

  - An out-of-bounds read error exists in the
    phar_parse_pharfile() function in phar.c due to improper
    parsing of phar archives. An unauthenticated, remote
    attacker can exploit this to cause a crash, resulting in
    a denial of service condition. (VulnDB 149621)

  - Multiple stored cross-site scripting (XSS)
    vulnerabilities exist in unspecified scripts due to a
    failure to validate input before returning it to users.
    An authenticated, remote authenticated attacker can
    exploit these, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (VulnDB 152085, 152086, 152087, 152088)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/tns-2017-04");
  script_set_attribute(attribute:"see_also", value:"https://httpoxy.org");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.4.3 or later.
Alternatively, apply the appropriate patch according to the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_keys("Host/SecurityCenter/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

version = get_kb_item("Host/SecurityCenter/Version");
if(empty_or_null(version))
  audit(AUDIT_UNKNOWN_APP_VER, "SecurityCenter");

fix = "5.4.3";

# Affects 5.0.2, 5.1.0, 5.2.0, 5.3.1, 5.3.2, 5.4.0, 5.4.1, 5.4.2
if ( version =~ "^5\.(0\.2|1\.0|2\.0|3\.[12]|4\.[0-2])([^0-9]|$)" )
{
  items = make_array(
    "Installed version", version,
    "Fixed version", fix
  );

  order = make_list("Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report, xss:TRUE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
