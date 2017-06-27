#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26967);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_name(english:"MagniComp SysInfo Agent Accessible");
  script_summary(english:"Tries to retrieve system info");

 script_set_attribute(attribute:"synopsis", value:
"The remote MagniComp SysInfo agent is not protected." );
 script_set_attribute(attribute:"description", value:
"The MagniComp SysInfo agent on the remote host allows the Nessus
server to retrieve information about the system's assets and
configuration, which could help an attacker plan more focused attacks
against the affected host." );
 script_set_attribute(attribute:"solution", value:
"Edit the AUTH and/or ALLOW keyword settings in the mcsysinfod
configuration file to limit access." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/10");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/mcsysinfod", 11967);

  exit(0);
}


port = get_kb_item("Services/mcsysinfod");
if (!port) port = 11967;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read the banner.
banner = "";
while (s = recv_line(socket:soc, length:1024))
{
  s = chomp(s);
  banner += s + '\n';
  if (s =~ "^\* ") break;
}
if (strlen(banner) && "SysInfo Server" >< banner && " talk AUTH" >!< banner)
{
  # nb: possible info classes include "all", "General", "Hardware", "FileSys", 
  #    "Partition", "NetIf", "Network, "VmHost", "Printer", "Patch", "Software",
  #    "License", "Service, "SiteInfo", "device". And the output format
  #    depends on the chosen class.
  class = "General";
  c = "SEND " + class;
  send(socket:soc, data:string(c, "\n"));

  info = "";
  while (s = recv_line(socket:soc, length:1024))
  {
    s = chomp(s);
    if (s =~ "^\* OK") break;
    if (s =~ "^general|")
    {
      f = split(s, sep:"|", keep:FALSE);
      if (strlen(f[3]) && strlen(f[4]))
        info += "  " + f[3] + " : " + crap(data:" ", length:35-strlen(f[3])) + f[4] + '\n';
    }
  }

  if (info)
  {
    report = string(
      "Nessus was able to collect the following info by querying the MagniComp",
      "SysInfo agent on the remote host :\n",
      "\n",
      info
    );
    security_warning(port:port, extra:report);
  }
}
close(soc);
