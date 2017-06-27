#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31118);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2017/01/30 15:10:02 $");

  script_cve_id("CVE-2007-5000","CVE-2007-6203","CVE-2007-6388","CVE-2007-6421","CVE-2007-6422","CVE-2008-0005");
  script_bugtraq_id(26663, 26838, 27234, 27236, 27237);
  script_osvdb_id(39003, 39133, 39134, 40262, 40263, 40264, 42214, 42937);

  script_name(english:"Apache 2.2.x < 2.2.8 Multiple Vulnerabilities (XSS, DoS)");
  script_summary(english:"Checks version in Server response header");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.2.x running on the
remote host is prior to 2.2.8. It is, therefore, affected by the
following vulnerabilities :

  - A cross-site scripting issue involving mod_imagemap
    (CVE-2007-5000).

  - A cross-site scripting issue involving 413 error pages
    via a malformed HTTP method (PR 44014 / CVE-2007-6203).

  - A cross-site scripting issue in mod_status involving 
    the refresh parameter (CVE-2007-6388).

  - A cross-site scripting issue in mod_proxy_balancer
    involving the worker route and worker redirect 
    string of the balancer manager (CVE-2007-6421).

  - A denial of service issue in the balancer_handler
    function in mod_proxy_balancer can be triggered by
    an authenticated user when a threaded Multi-
    Processing Module is used (CVE-2007-6422).

  - A cross-site scripting issue using UTF-7 encoding
    in mod_proxy_ftp exists because it does not 
    define a charset (CVE-2008-0005).

Note that the remote web server may not actually be affected by these
vulnerabilities. Nessus did not try to determine whether the affected
modules are in use or to check for the issues themselves.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.2");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.2.8 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

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
# was used
if (version =~ '^2(\\.2)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
if (version =~ '^2\\.2' && ver_compare(ver:version, fix:'2.2.8') == -1)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.2.8\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "Apache "+version+" is listening on port "+port+" and is not affected.");
