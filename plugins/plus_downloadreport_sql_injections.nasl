#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23840);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2012/10/30 13:23:00 $");

  script_cve_id("CVE-2006-6450");
  script_bugtraq_id(21473);
  script_osvdb_id(31355);

  script_name(english:"PatchLink Update /dagent/downloadreport.asp Multiple Parameter SQL Injection");
  script_summary(english:"Tries to exploit SQL injection issue in PatchLink Update");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is prone to SQL
injection attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running PatchLink Update Server, a patch and
vulnerability management solution. 

The version of PatchLink Update Server installed on the remote fails to
sanitize user-supplied input to the 'agentid' and 'pass' parameters of
the '/dagent/downloadreport.asp' script before using it to construct
database queries.  An unauthenticated attacker can exploit this flaw to
manipulate database queries, which might lead to disclosure of sensitive
information, modification of data, or attacks against the underlying
database. 

Note that Novell ZENworks Patch Management is based on PatchLink Update
server and is affected as well.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.3.2.700 if using Novell ZENworks Patch
Management.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:novell:zenworks_patch_management_server");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_asp(port:port)) exit(0);


# Try to exploit the flaw to generate a SQL error.
r = http_send_recv3(
  item:string(
    "/dagent/downloadreport.asp?",
    "agentid=1111&",
    "pass=2", urlencode(str:string(";SELECT ", SCRIPT_NAME))
  ),
  method:"GET",
  port:port
);
if (isnull(r)) exit(0);
res = r[2];


# There's a problem if we see an error with our script name.
if (
  "Microsoft OLE DB Provider for SQL Server" >< res &&
  "error '80040e14'" >< res &&
  # nb: the error message does not include the script's extension.
  string("The column prefix '", (SCRIPT_NAME - strstr(SCRIPT_NAME, "."))) >< res
) {
 security_hole(port);
 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}


