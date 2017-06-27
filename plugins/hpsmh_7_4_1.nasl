#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85181);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/24 13:12:22 $");

  script_cve_id(
    "CVE-2014-3508",
    "CVE-2014-3509",
    "CVE-2014-3511",
    "CVE-2014-3513",
    "CVE-2014-3566",
    "CVE-2014-3567",
    "CVE-2014-3568",
    "CVE-2014-5139",
    "CVE-2015-2133"
  );
  script_bugtraq_id(
    69075,
    69077,
    69079,
    69084,
    70574,
    70584,
    70585,
    70586,
    75434
  );
  script_osvdb_id(
    109894,
    109896,
    109898,
    109902,
    113251,
    113373,
    113374,
    113377,
    125014
  );
  script_xref(name:"HP", value:"HPSBMU03375");
  script_xref(name:"HP", value:"emr_na-c04743386");
  script_xref(name:"HP", value:"SSRT101710");
  script_xref(name:"HP", value:"HPSBMU03260");
  script_xref(name:"HP", value:"emr_na-c04571379");
  script_xref(name:"HP", value:"SSRT101894");
  script_xref(name:"CERT", value:"577193");

  script_name(english:"HP System Management Homepage < 7.2.5 / 7.4.1 Multiple Vulnerabilities (POODLE)");
  script_summary(english:"Checks version in the banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the web server's banner, the version of HP System
Management Homepage (SMH) hosted on the remote web server is prior to
7.2.5 or 7.4.1. It is, therefore, affected by the following 
vulnerabilities :

  - An information disclosure vulnerability exists exists in
    OpenSSL due to the pretty printing functions leaking
    information from the stack. A remote attacker can
    exploit this to disclose sensitive information that is
    echoed from pretty printing output. (CVE-2014-3508)

  - A race condition exists in OpenSSL that is triggered
    when handling Elliptic Curve (EC) Point Format Extension
    data in a resumed session. A remote attacker can exploit
    this to corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code.
    (CVE-2014-3509)

  - A flaw exists in OpenSSL related to handling fragmented
    'ClientHello' messages that allows a man-in-the-middle
    attacker to force usage of TLS 1.0 regardless of higher
    protocol levels being supported by both the server and
    the client. (CVE-2014-3511)

  - A denial of service vulnerability exists in OpenSSL in
    the DTLS SRTP extension parsing code due to improper
    handling of handshake messages. A remote attacker can
    exploit this, via a specially crafted handshake message,
    to cause a memory leak, resulting in a denial of
    service. (CVE-2014-3513)

  - A man-in-the-middle (MitM) information disclosure
    vulnerability, known as POODLE, exists due to the way
    SSL 3.0 handles padding bytes when decrypting messages
    encrypted using block ciphers in cipher block chaining
    (CBC) mode. A MitM attacker can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections.
    (CVE-2014-3566)

  - A denial of service vulnerability exists in OpenSSL due
    to a failure to properly verify the integrity of session
    tickets. A remote attacker can exploit this, via a large
    number of invalid session tickets, to cause a memory
    leak, resulting in a denial of service condition.
    (CVE-2014-3567)

  - An error exists in OpenSSL related to the build
    configuration process and the 'no-ssl3' build option
    that allows servers and clients to process insecure SSL
    3.0 handshake messages. (CVE-2014-3568)

  - A NULL pointer dereference flaw exists in OpenSSL that
    is triggered when an SRP ciphersuite is specified
    without being properly negotiated with the client. A
    remote attacker controlling a malicious server can
    exploit this to crash an OpenSSL client. (CVE-2014-3569)

  - A remote code execution vulnerability exists due to a
    buffer overflow condition in the Single Sign On (SSO)
    module. A remote attacker, using a long parameter, can
    exploit this to execute arbitrary code in the context of
    SYSTEM. (CVE-2015-2133)

Note that these vulnerabilities only affect instances of SMH running
on Windows and Linux hosts.");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=c04743386
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15dd8325");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04571379
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a5380ec");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-262/");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP System Management Homepage (SMH) 7.2.5 / 7.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/03");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

get_kb_item_or_exit("www/hp_smh");

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

fixed_version = NULL;

if (ver_compare(ver:version_alt, fix:'7.2.5', strict:FALSE) == -1)
  fixed_version = '7.2.5';
else if (
  version_alt =~ "^7\.[34]([^0-9]|$)" &&
  ver_compare(ver:version_alt, fix:'7.4.1', strict:FALSE) == -1
)
  fixed_version = '7.4.1';

if (isnull(fixed_version))
  audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);

source_line = get_kb_item("www/"+port+"/hp_smh/source");

report = '\n  Product           : ' + prod;
if (!isnull(source_line))
  report += '\n  Version source    : ' + source_line;
report +=
  '\n  Installed version : ' + version_alt +
  '\n  Fixed version     : ' + fixed_version +
  '\n';

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
