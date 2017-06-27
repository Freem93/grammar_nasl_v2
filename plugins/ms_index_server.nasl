#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10356);
 script_version("$Revision: 1.41 $");
 script_cvs_date("$Date: 2014/05/26 01:15:51 $");

 script_cve_id("CVE-2000-0097", "CVE-2000-0302");
 script_bugtraq_id(950, 1084);
 script_osvdb_id(271, 1210);
 script_xref(name:"MSFT", value:"MS00-006");

 script_name(english:"Microsoft IIS WebHits null.htw .asp Source Disclosure");
 script_summary(english:"Checks for a problem in webhits.dll");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It is possible to get the source code of ASP scripts by issuing a
specially crafted request.

ASP source codes usually contain sensitive information such as
usernames and passwords.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms00-006");
 script_set_attribute(attribute:"solution", value:"Apply the patches referenced above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/01");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl", "webmirror.nasl", "www_fingerprinting_hmap.nasl");
 script_require_keys("Settings/ParanoidReport", "www/ASP");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if(!can_host_asp(port:port)) exit(0);

function check(file)
{
  local_var res;

  res = http_send_recv3(method:"GET", item:string("/null.htw?CiWebHitsFile=", file, "%20&CiRestriction=none&CiHiliteType=Full"), port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  res[2] = tolower(res[2]);
  if ("&lt;html&gt;" >< res[2]){
    security_warning(port);
    exit(0);
  }
  else exit(0);
 return(0);
}

check(file:"/default.asp");
files = get_kb_list(string("www/", port, "/content/extensions/asp"));
if(isnull(files))exit(0);
files = make_list(files);
check(file:files[0]);
