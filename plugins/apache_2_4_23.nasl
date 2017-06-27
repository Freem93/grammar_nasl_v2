#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92320);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/16 16:05:32 $");

  script_cve_id("CVE-2016-4979");
  script_bugtraq_id(91566);
  script_osvdb_id(140986);

  script_name(english:"Apache 2.4.18 / 2.4.20 X.509 Certificate Authentication Bypass");
  script_summary(english:"Checks the version in the server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache running on the remote
host is either 2.4.18 or 2.4.20. Additionally, HTTP/2 is enabled over
TLS or SSL. It is, therefore, affected by the an authentication bypass
vulnerability in the experimental module for the HTTP/2 protocol due
to a failure to correctly validate X.509 certificates, allowing access
to resources that otherwise would not be allowed. An unauthenticated,
remote attacker can exploit this to disclose potentially sensitive
information.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.23");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2016/Jul/11");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.23 or later. Alternatively, as a
temporary workaround, HTTP/2 can be disabled by changing the
configuration by removing 'h2' and 'h2c' from the Protocols line(s)
in the configuration file.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("alpn_protocol_enumeration.nasl", "apache_http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:443);

# if not apache
get_kb_item_or_exit("www/"+port+"/apache");

# see if http/2 is enabled (not h2c)
# this vuln has to do with x509 client cert verification
protos = get_kb_list("SSL/ALPN/"+port);
found = FALSE;

if (!isnull(protos))
{
  proto_list = make_list(protos);
  foreach proto (proto_list)
  {
    if (proto == 'h2')
    {
      found = TRUE;
      break;
    }
  }
}

if (!found) audit(AUDIT_NOT_DETECT, "An h2-enabled Apache web server", port);

# Check if we could get a version
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Ensure granularity
if (version =~ '^2(\\.4)?$') audit(AUDIT_VER_NOT_GRANULAR, 'Apache', port, version);

if (version == "2.4.18" || version == "2.4.20")
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 2.4.23\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, version);
