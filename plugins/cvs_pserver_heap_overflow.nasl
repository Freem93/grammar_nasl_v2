#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(12240);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2014/05/12 23:23:17 $");

 script_cve_id("CVE-2004-0396");
 script_bugtraq_id(10384);
 script_osvdb_id(6305);

 script_name(english:"CVS pserver Line Entry Handling Overflow");
 script_summary(english:"Logs into the remote CVS server and asks the version");

 script_set_attribute(attribute:"synopsis", value:
"The remote version control service has a remote heap-based buffer
overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote CVS server has a heap-
based buffer overflow vulnerability.  A remote attacker could exploit
this to crash the service, or possibly execute arbitrary code.");
 # http://web.archive.org/web/20050828060507/http://security.e-matters.de/advisories/072004.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?ac6e8d97"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to CVS 1.12.8 / 1.11.16 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/05/19");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service1.nasl", "cvs_public_pserver.nasl");

 exit(0);
}

include('global_settings.inc');

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);

login = get_kb_item(string("cvs/", port, "/login"));
pass  = get_kb_item(string("cvs/", port, "/pass"));
dir   = get_kb_item(string("cvs/", port, "/dir"));

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = string("BEGIN AUTH REQUEST\n",
dir, "\n",
login,"\n",
"A", pass,"\n",
"END AUTH REQUEST\n");

  send(socket:soc, data:req);
  r = recv_line(socket:soc, length:4096);
  if("I LOVE YOU" >< r)
  {
    send(socket:soc, data:string("version\n"));
    r = recv_line(socket:soc, length:4096);
    if("Concurrent" >< r)
    {
     set_kb_item(name:string("cvs/", port, "/version"), value:r);
     if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|1[0-5])|12\.[0-7][^0-9]).*", string:r))
     {
        rep = strcat('\nThe CVS pserver version is : ', r, '\n');
     	security_hole(port:port, extra: rep);
     }
    }
  }
  close(soc);
 
