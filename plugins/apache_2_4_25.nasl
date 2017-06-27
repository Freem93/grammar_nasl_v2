#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96451);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/13 17:57:45 $");

  script_cve_id(
    "CVE-2016-0736",
    "CVE-2016-2161",
    "CVE-2016-5387",
    "CVE-2016-8740",
    "CVE-2016-8743"
  );
  script_bugtraq_id(
    91816,
    94650,
    95076,
    95077,
    95078
  );
  script_osvdb_id(
    141669,
    148143,
    148286,
    148338,
    149054
  );
  script_xref(name:"CERT", value:"797896");
  script_xref(name:"IAVA", value:"2017-A-0010");
  script_xref(name:"EDB-ID", value:"40961");

  script_name(english:"Apache 2.4.x < 2.4.25 Multiple Vulnerabilities (httpoxy)");
  script_summary(english:"Checks the version in the server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache running on the remote
host is 2.4.x prior to 2.4.25. It is, therefore, affected by the
following vulnerabilities :

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
    (CVE-2016-5387)

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

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/dev/dist/Announcement2.4.html");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apache/httpd/blob/2.4.x/CHANGES");
  script_set_attribute(attribute:"see_also", value:"https://www.apache.org/security/asf-httpoxy-response.txt");
  script_set_attribute(attribute:"see_also", value:"https://httpoxy.org");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.25 or later.

Note that the 'httpoxy' vulnerability can be mitigated by applying the
workarounds or patches as referenced in the vendor advisory
asf-httpoxy-response.txt. Furthermore, to mitigate the other
vulnerabilities, ensure that the affected modules (mod_session_crypto,
mod_auth_digest, and mod_http2) are not in use.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("vcf.inc");
include("http.inc");

port = get_http_port(default:80);
get_kb_item_or_exit('www/'+port+'/apache');

kb_base = 'www/apache/' + port + '/';
app_info = vcf::get_app_info(
  app:"Apache",
  port:port,
  kb_ver:kb_base+'version',
  kb_backport:kb_base+'backported',
  kb_source:kb_base+'source',
  service:TRUE
);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version":"2.3", "fixed_version":"2.4.25" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
