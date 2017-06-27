#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11552);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

 script_bugtraq_id(7388, 7393);
 script_osvdb_id(55813, 55814);

 script_name(english:"mod_ntlm for Apache Multiple Remote Vulnerabilities");
 script_summary(english:"mod_ntlm overflow / format string");

 script_set_attribute(attribute:"synopsis", value:"The remote web server module has multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running mod_ntlm, a NTLM authentication
module for Apache. This version of mod_ntlm has a buffer overflow and
a format string vulnerability. A remote attacker could exploit these
issues to execute arbitrary code.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Apr/255");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9513a21e");
 script_set_attribute(attribute:"solution", value:"Apply the vendor patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/26");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_keys("www/apache", "Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

function check(loc)
{
  local_var w, res, soc, r;

  w = http_send_recv3(method:"GET",item:loc, port:port,
    username: "", password: "");
  if (isnull(w)) exit(1, "the web server did not answer");

  if("WWW-Authenticate: NTLM" >< w[1] )
  {
    w = http_send_recv3(method: "GET", item: loc, port: port,
      add_headers: make_array("Authorization", "NTLM nnnn"));
    if (isnull(w)) exit(1, "the web server did not answer");

    w = http_send_recv3(method:"GET", item: loc, port: port,
      add_headers: make_array("Authorization", "NTLM %n%n%n%n"));

    if (isnull(w))
    {
      security_hole(port);
      exit(0);
    }
   }
}

pages = get_kb_list(string("www/", port, "/content/auth_required"));
if(isnull(pages)) pages = make_list("/");
else pages = make_list("/", pages);


foreach page (pages)
{
 check(loc:page);
}
