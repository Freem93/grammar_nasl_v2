##
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# this script tests for the "You had me at hello" overflow
# in MSSQL (tcp/1433)
# Copyright Dave Aitel (2002)
# Bug found by: Dave Aitel (2002)
#
##
#TODO:
#techically we should also go to the UDP 1434 resolver service
#and get any additional ports!!!

# Changes by Tenable:
# - Revised plugin title (6/8/09)

include("compat.inc");

if (description)
{
  script_id(11067);
  script_version("$Revision: 1.36 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id("CVE-2002-1123");
  script_bugtraq_id(5411);
  script_osvdb_id(10132);
  script_xref(name:"MSFT", value:"MS02-056");

  script_name(english:"Microsoft SQL Server Authentication Function Remote Overflow");
  script_summary(english:"Microsoft SQL Hello Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL server is vulnerable to the Hello overflow.

An attacker may use this flaw to execute commands against the remote
host as LOCAL/SYSTEM, as well as read your database content.

*** This alert might be a false positive.");
  # http://web.archive.org/web/20031204044027/http://support.microsoft.com/default.aspx?scid=kb;en-us;Q316333&sd=tech
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32a9c483");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms02-056");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Aug/106");
  script_set_attribute(attribute:"solution", value:"Apply the patch from the Microsoft Bulletin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS02-056 Microsoft SQL Server Hello Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2002-2016 Dave Aitel");
  script_family(english:"Databases");

  script_dependencie("mssqlserver_detect.nasl", "mssql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(1433, "Services/mssql");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver_list = get_kb_list("mssql/installs/*/SQLVersion");
if (ver_list)
{
  do_check = FALSE;
  foreach item (keys(ver_list))
  {
    version = get_kb_item(item);
    if (!isnull(version) && ereg(pattern:"^8\.00\.(0?[0-5][0-9][0-9]|0?6[0-5][0-9]|66[0-4])", string:version))
    {
      do_check = TRUE;
      break;
    }
  }
  if (!do_check) exit(0, 'No potentially vulnerable installs of Microsoft SQL Server were detected.');
}

#
# The script code starts here
#
#taken from mssql.spk
pkt_hdr = raw_string(
0x12 ,0x01 ,0x00 ,0x34 ,0x00 ,0x00 ,0x00 ,0x00  ,0x00 ,0x00 ,0x15 ,0x00 ,0x06 ,0x01 ,0x00 ,0x1b
,0x00 ,0x01 ,0x02 ,0x00 ,0x1c ,0x00 ,0x0c ,0x03  ,0x00 ,0x28 ,0x00 ,0x04 ,0xff ,0x08 ,0x00 ,0x02
,0x10 ,0x00 ,0x00 ,0x00
);

#taken from mssql.spk
pkt_tail = raw_string (
0x00 ,0x24 ,0x01 ,0x00 ,0x00
);

#techically we should also go to the UDP 1434 resolver service
#and get any additional ports!!!
port = get_kb_item("Services/mssql");
if(!port)port = 1433;

found = 0;
report = "The Microsoft SQL Server install is vulnerable to the Hello overflow.";


if(get_port_state(port))
{
    soc = open_sock_tcp(port);

    if(soc)
    {
    	#uncomment this to see what normally happens
        #attack_string="MSSQLServer";
	#uncomment next line to actually test for overflow
	attack_string=crap(560);
        # this creates a variable called sql_packet
	sql_packet = string(pkt_hdr,attack_string,pkt_tail);
	send(socket:soc, data:sql_packet);
        r  = recv(socket:soc, length:4096);
	close(soc);
	#display ("Result:",r,"\n");
	if(!r)
	    {
	    # display("Security Hole in MSSQL\n");
            security_hole(port);
	    }
    }
}
