#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22117);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-3425");
  script_bugtraq_id(18723);
  script_osvdb_id(26926);

  script_name(english:"PatchLink Update Server proxyreg.asp Arbitrary Proxy Manipulation");
  script_summary(english:"Tries to list registered proxy server in PatchLink Update Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is prone to an
authentication bypass attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PatchLink Update Server, a patch and
vulnerability management solution. 

The version of PatchLink Update Server installed on the remote fails
to check for authentication credentials before providing access to the
'/dagent/proxyreg.asp' script.  An attacker can exploit this issue to
list, delete, or add proxies used by the PatchLink FastPatch software. 

Note that Novell ZENworks Patch Management is based on PatchLink
Update Server and is affected as well." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/438710/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://support.novell.com/cgi-bin/search/searchtid.cgi?10100709.htm" );
 script_set_attribute(attribute:"solution", value:
"Apply patch 6.1 P1 / 6.2 SR1 P1 if using PatchLink Update Server or
6.2 SR1 P1 if using Novell ZENworks Patch Management." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/28");
 script_cvs_date("$Date: 2011/03/14 21:48:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_asp(port:port)) exit(0);


# Try to list registered proxy servers.
r = http_send_recv3(method:"GET", item:"/dagent/proxyreg.asp?List=", port:port);
if (isnull(r)) exit(0);
res = r[2];

# There's a problem if we get a listing.
if ("registered as distribution point servers for this PatchLink Update Server" >< res)
{
  # Identify proxies.
  proxies = "";
  content = res;
  while (content = strstr(content, "<tr><td>"))
  {
    match = eregmatch(pattern:"<tr><td>([^<]+)</td><td>([^<]+)</td", string:content);
    if (match) proxies += "  " + match[1] + ":" + match[2] + '\n';
    content = content - "<tr><td>";
  }
  if (!proxies) proxies = "  none";

  report = string(
    "The following is the list of currently configured proxies :\n",
    "\n",
    proxies
  );
  security_hole(port:port, extra:report);
}
