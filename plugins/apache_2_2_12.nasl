#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40467);
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");
  script_version("$Revision: 1.21 $");

  script_cve_id(
    "CVE-2009-0023",
    "CVE-2009-1191",
    "CVE-2009-1195",
    "CVE-2009-1890",
    "CVE-2009-1891",
    "CVE-2009-1955",
    "CVE-2009-1956"
  );
  script_bugtraq_id(34663, 35115, 35221, 35251, 35253, 35565, 35623);
  script_osvdb_id(53921, 54733, 55057, 55058, 55059, 55553, 55782);

  script_name(english:"Apache 2.2.x < 2.2.12 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server may be affected by several issues."
  );
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.2.x. running on the
remote host is prior to 2.2.12. It is, therefore, affected by the
following vulnerabilities :

  - A heap-based buffer underwrite flaw exists in the
    function 'apr_strmatch_precompile()' in the bundled copy
    of the APR-util library, which could be triggered when
    parsing configuration data to crash the daemon.
    (CVE-2009-0023)

  - A flaw in the mod_proxy_ajp module in version 2.2.11
    only may allow a remote attacker to obtain sensitive
    response data intended for a client that sent an
    earlier POST request with no request body.
    (CVE-2009-1191)

  - The server does not limit the use of directives in a
    .htaccess file as expected based on directives such
    as 'AllowOverride' and 'Options' in the configuration
    file, which could enable a local user to bypass
    security restrictions. (CVE-2009-1195)

  - Failure to properly handle an amount of streamed data
    that exceeds the Content-Length value allows a remote
    attacker to force a proxy process to consume CPU time
    indefinitely when mod_proxy is used in a reverse proxy
    configuration. (CVE-2009-1890)

  - Failure of mod_deflate to stop compressing a file when
    the associated network connection is closed may allow a
    remote attacker to consume large amounts of CPU if
    there is a large (>10 MB) file available that has
    mod_deflate enabled. (CVE-2009-1891)

  - Using a specially crafted XML document with a large
    number of nested entities, a remote attacker may be
    able to consume an excessive amount of memory due to
    a flaw in the bundled expat XML parser used by the
    mod_dav and mod_dav_svn modules. (CVE-2009-1955)

  - There is an off-by-one overflow in the function
    'apr_brigade_vprintf()' in the bundled copy of the
    APR-util library in the way it handles a variable list
    of arguments, which could be leveraged on big-endian
    platforms to perform information disclosure or denial
    of service attacks. (CVE-2009-1956)

Note that Nessus has relied solely on the version in the Server
response header and did not try to check for the issues themselves or
even whether the affected modules are in use."  );
  script_set_attribute(attribute:"see_also",  value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_set_attribute(attribute:"solution",  value:
"Upgrade to Apache version 2.2.12 or later. Alternatively, ensure that
the affected modules / directives are not in use.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 119, 189, 399);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/02");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure this is Apache.
get_kb_item_or_exit('www/'+port+'/apache');

# Check if we could get a version first, then check if it was 
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) exit(1, "Security Patches may have been backported.");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokens Major/Minor
# was  used
if (version =~ '^2(\\.2)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
if (version =~ '^2\\.2' && ver_compare(ver:version, fix:'2.2.12') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 2.2.12\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "Apache "+version+" is listening on port "+port+" and is not affected.");
