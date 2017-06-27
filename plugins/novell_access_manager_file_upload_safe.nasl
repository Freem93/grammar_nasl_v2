#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47582);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/05/18 00:28:48 $");

  script_cve_id("CVE-2010-0284");
  script_bugtraq_id(40931, 43635);
  script_osvdb_id(65629, 68320);
  script_xref(name:"Secunia", value:"40198");
  script_xref(name:"Secunia", value:"41687");

  script_name(english:"Novell 'modulemanager' Servlet Arbitrary File Upload (safe check)");
  script_summary(english:"Checks if the affected servlet does not require authentication");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has an arbitrary file upload
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Administration Console component of Novell Access Manager or
Novell iManager running on the remote web server has an arbitrary
file upload vulnerability.  Sending a specially crafted multipart
POST request to '/nps/servlet/modulemanager' results in the upload
of arbitrary data. Specifying a destination filename that contains
a directory traversal string allows an attacker to write arbitrary
files as SYSTEM.  Only Windows installs are affected.

A remote attacker could exploit this to upload arbitrary files to the
system, resulting in remote code execution. 

Since safe checks are enabled, Nessus fingerprinted the vulnerable
servlet by sending innocuous requests and checking the HTTP response
codes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-112/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc3c7407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-190/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.novell.com/support/viewContent.do?externalId=7006515"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Access Manager 3.1 SP2 / iManager 2.7 ftf3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Novell iManager File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Novell iManager getMultiPartParameters Arbitrary File Upload');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/06/10");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8443);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# Unless we're paranoid, bail out if OS has been determined and is not Windows
if (report_paranoia < 2)
{
  os = get_kb_item('Host/OS');
  if (os && 'Windows' >!< os)
    exit(0, 'Only Windows hosts are affected.');
}

port = get_http_port(default:8443);


function get_http_code()
{
  local_var res, headers, http_code;
  res = _FCT_ANON_ARGS[0];
  if (isnull(res)) return NULL;

  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  if (isnull(headers)) exit(1, 'Error parsing HTTP headers on port '+port+'.');

  http_code = headers['$code'];
  if (isnull(http_code)) exit(1, "Error parsing HTTP response code");

  return http_code;
}


# key - query string, value - expected http response code
tests = make_array(
  '?MODULE_PATH=/etc/passwd&'+SCRIPT_NAME+'='+unixtime(), 400,
  '', 417
);

servlet = '/nps/servlet/modulemanager';

foreach qs (keys(tests))
{
  url = servlet + qs;
  expected_code = tests[qs];
  res = http_send_recv3(method:'GET', port:port, item:url, exit_on_fail:TRUE);
  code = get_http_code(res);

  if (code != expected_code)
    exit(0, 'The server on port '+port+' is not affected.');
}

security_hole(port);
