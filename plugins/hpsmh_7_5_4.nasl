#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90150);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/15 04:41:37 $");

  script_cve_id(
    "CVE-2015-1788",
    "CVE-2015-1789",
    "CVE-2015-1790",
    "CVE-2015-1791",
    "CVE-2015-1792",
    "CVE-2015-1793",
    "CVE-2015-3143",
    "CVE-2015-3145",
    "CVE-2015-3148",
    "CVE-2015-4000",
    "CVE-2015-4024",
    "CVE-2016-1993",
    "CVE-2016-1994",
    "CVE-2016-1995",
    "CVE-2016-1996"
  );
  script_bugtraq_id(
    74299,
    74301,
    74303,
    74733,
    74903,
    75154,
    75156,
    75157,
    75158,
    75161,
    75652
  );
  script_osvdb_id(
    121128,
    121129,
    121130,
    122127,
    122331,
    122875,
    123172,
    123173,
    123174,
    123175,
    124300,
    136045,
    136046,
    136047,
    136048
  );
  script_xref(name:"HP", value:"HPSBMU03546");
  script_xref(name:"HP", value:"emr_na-c05045763");
  script_xref(name:"HP", value:"SSRT101447");
  script_xref(name:"HP", value:"SSRT101858");
  script_xref(name:"HP", value:"SSRT102109");
  script_xref(name:"HP", value:"SSRT102164");
  script_xref(name:"HP", value:"PSRT110050");

  script_name(english:"HP System Management Homepage < 7.5.4 Multiple Vulnerabilities (Logjam)");
  script_summary(english:"Checks the banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the web server's banner, the version of HP System
Management Homepage (SMH) hosted on the remote web server is a version
prior to 7.5.4. It is, therefore, affected by the following
vulnerabilities :

  - A denial of service vulnerability exists when processing
    an ECParameters structure due to an infinite loop that
    occurs when a specified curve is over a malformed binary
    polynomial field. A remote attacker can exploit this to
    perform a denial of service against any system that
    processes public keys, certificate requests, or
    certificates. This includes TLS clients and TLS servers
    with client authentication enabled. (CVE-2015-1788) 

  - A denial of service vulnerability exists due to improper
    validation of the content and length of the ASN1_TIME
    string by the X509_cmp_time() function. A remote
    attacker can exploit this, via a malformed certificate
    and CRLs of various sizes, to cause a segmentation
    fault, resulting in a denial of service condition. TLS
    clients that verify CRLs are affected. TLS clients and
    servers with client authentication enabled may be
    affected if they use custom verification callbacks.
    (CVE-2015-1789)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing inner
    'EncryptedContent'. This allows a remote attacker, via
    specially crafted ASN.1-encoded PKCS#7 blobs with
    missing content, to cause a denial of service condition
    or other potential unspecified impacts. (CVE-2015-1790)

  - A double-free error exists due to a race condition that
    occurs when a NewSessionTicket is received by a
    multi-threaded client when attempting to reuse a
    previous ticket. (CVE-2015-1791)

  - A denial of service vulnerability exists in the CMS code
    due to an infinite loop that occurs when verifying a
    signedData message. A remote attacker can exploit this
    to cause a denial of service condition. (CVE-2015-1792)

  - A certificate validation bypass vulnerability exists in
    the Security:Encryption subcomponent due to a flaw in
    the X509_verify_cert() function in x509_vfy.c that is
    triggered when locating alternate certificate chains
    when the first attempt to build such a chain fails. A
    remote attacker can exploit this, by using a valid leaf
    certificate as a certificate authority (CA), to issue
    invalid certificates that will bypass authentication.
    (CVE-2015-1793)

  - A cross-request authentication bypass vulnerability
    exists in libcurl due to the use of an existing,
    authenticated connection when performing a subsequent
    unauthenticated NTLM HTTP request. An attacker can
    exploit this to bypass authentication mechanisms.
    (CVE-2015-3143)

  - A denial of service vulnerability exists in libcurl due
    to a flaw in the sanitize_cookie_path() function that is
    triggered when handling a cookie path element that
    consists of a single double-quote. An attacker can
    exploit this to cause the application to crash.
    (CVE-2015-3145)

  - A cross-request authentication bypass vulnerability
    exists in libcurl due to a flaw that is triggered when a
    request is 'Negotiate' authenticated, which can cause
    the program to treat the entire connection as
    authenticated rather than just that specific request. An
    attacker can exploit this to bypass authentication
    mechanisms for subsequent requests. (CVE-2015-3148)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)

  - A flaw exists in the multipart_buffer_headers() function
    in rfc1867.c due to improper handling of
    multipart/form-data in HTTP requests. A remote attacker
    can exploit this flaw to cause a consumption of CPU
    resources, resulting in a denial of service condition.
    (CVE-2015-4024)

  - An unspecified flaw exists that allows an authenticated,
    remote attacker to impact confidentiality and integrity.
    (CVE-2016-1993)

  - An unspecified information disclosure vulnerability
    exists that allows an authenticated, remote attacker to
    gain unauthorized access to information. (CVE-2016-1994)

  - An unspecified remote code execution vulnerability
    exists that allows an unauthenticated, remote attacker
    to take complete control of the system. (CVE-2016-1995)

  - An unspecified flaw exists that allows a local attacker
    to impact confidentiality and integrity. (CVE-2016-1996)");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05045763
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4248fa41");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP System Management Homepage (SMH) version 7.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/24");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/hp_smh");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port    = get_http_port(default:2381, embedded:TRUE);

install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
dir     = install['dir'];
version = install['ver'];
prod    = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");

if (version == UNKNOWN_VER) exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' is unknown.');

# Only Linux and Windows are affected -- HP-UX is not mentioned
if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Windows" >!< os && "Linux" >!< os) audit(AUDIT_OS_NOT, "Windows or Linux", os);
}

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt)) exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' does not look valid ('+version+').');

fixed_version = '7.5.4';
if (ver_compare(ver:version_alt, fix:fixed_version, strict:FALSE) == -1)
{
  source_line = get_kb_item("www/"+port+"/hp_smh/source");
  report = '\n  Product           : ' + prod;
  if (!isnull(source_line))
    report += '\n  Version source    : ' + source_line;
  report +=
    '\n  Installed version : ' + version_alt +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
