#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35760);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/21 20:41:39 $");

  script_bugtraq_id(33928);
  script_osvdb_id(55847, 79148);
  script_xref(name:"Secunia", value:"34086");

  script_name(english:"Novell eDirectory < 8.8 SP3 FTF3 iMonitor HTTP Accept-Language Header Overflow");
  script_summary(english:"Checks version of eDirectory from an ldap search");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running eDirectory, a directory service software
from Novell. The iMonitor component included with the installed version
is affected by a buffer overflow vulnerability. By sending a specially
crafted HTTP request to the iMonitor component with a malformed
'Accept-Language' header, it may be possible for a remote attacker
to execute arbitrary code on the remote system.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?714d89e9");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?671a8b0f");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d17f8b20");
  script_set_attribute(attribute:"solution", value:"Upgrade to eDirectory 8.8 SP3 with FTF3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/03");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:edirectory");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl","http_version.nasl");
  script_require_ports("Services/ldap", 389, "Services/www", 8028, 8030);

  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");


http_port = NULL;
if (report_paranoia < 2)
{
  found = 0;
  ports = add_port_in_list(list:get_kb_list("Services/www"), port:8028);
  ports = add_port_in_list(list:ports, port:8030);

  foreach port (ports)
  {
    banner = get_http_banner (port:port);
    if(!isnull(banner))
    {
      if (egrep(pattern:"Server: .*HttpStk/[0-9]+\.[0-9]+", string:banner))
      {
        res = http_send_recv3(method:"GET", item:"/", port:port);
        if(!isnull(res) && "NDS iMonitor" >< res[2])
        {
          http_port = port;
          found = 1;
          break;
        }
      }
    }
  }
  if(!found) exit(0);
}
if(isnull(http_port)) http_port = 0;


ldap_port = get_kb_item("Services/ldap");
if (isnull(ldap_port)) ldap_port = 389;
if (!get_port_state(ldap_port)) exit(1,"Port "+ ldap_port + " is not open.");

edir_ldap = get_kb_item(string("LDAP/",ldap_port,"/vendorVersion"));
if (isnull(edir_ldap) || "Novell eDirectory" >!< edir_ldap) exit(0);

maj_min = NULL;
min_min = NULL;

if ("Novell eDirectory 8.8 SP3" >< edir_ldap)
{
  match = eregmatch(pattern:"LDAP Agent for Novell eDirectory 8.8 SP3 \(([0-9]+)\.([0-9]+)\)",string:edir_ldap);
  maj_min = match[1];
  min_min = match[2];
}

# KB entries past and present.

# LDAP Agent for Novell eDirectory 8.7.3.10 (10555.95)
# LDAP Agent for Novell eDirectory 8.7.3 (10552.72)
# LDAP Agent for Novell eDirectory 8.8 (20114.35)
# LDAP Agent for Novell eDirectory 8.8 SP1 (20114.57) # unpatched
# LDAP Agent for Novell eDirectory 8.8 SP2 (20216.46) # unpatched
# LDAP Agent for Novell eDirectory 8.8 SP3 (20216.73) # unpatched
# LDAP Agent for Novell eDirectory 8.8 SP3 (20216.80) # patched

if ( ereg(pattern:"^LDAP Agent for Novell eDirectory ([0-7]\.|8.[0-7]([^0-9]|$))",string:edir_ldap)  	                    ||
     ereg(pattern:"^LDAP Agent for Novell eDirectory 8.8 *SP[12] *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap)                ||
     ereg(pattern:"^LDAP Agent for Novell eDirectory 8.8 *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap)	                    ||
     ("Novell eDirectory 8.8 SP3" >< edir_ldap && !isnull(maj_min) && maj_min < 20216 )			                    ||
     ("Novell eDirectory 8.8 SP3" >< edir_ldap && !isnull(maj_min) && !isnull(min_min) && maj_min == 20216 && min_min < 80)
   )
{
  if (report_verbosity > 0)
  {
    edir_product = strstr(edir_ldap,"Novell eDirectory");

    report = string(
      "\n",
      edir_product, " is installed on the remote host.\n"
    );
    security_hole(port:http_port, extra:report);
  }
  else security_hole(http_port);
}
