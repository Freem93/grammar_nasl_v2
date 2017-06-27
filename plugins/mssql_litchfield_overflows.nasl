#
# (C) Tenable Network Security, Inc.
#

#
# ping code taken from mssql_ping by H D Moore
#
#
# MS02-061 supercedes MS02-020, MS02-038, MS02-039, MS02-043 and MS02-056
#
# BID xref by Erik Anderson <eanders@carmichaelsecurity.com>
#
# Other CVEs: CVE-2002-0729, CVE-2002-0650
#

include("compat.inc");

if (description)
{
 script_id(11214);
 script_version("$Revision: 1.49 $");
 script_cvs_date("$Date: 2017/02/10 14:51:43 $");

 script_cve_id("CVE-2002-1137", "CVE-2002-1138", "CVE-2002-0649", "CVE-2002-0650",
               "CVE-2002-1145", "CVE-2002-0644", "CVE-2002-0645", "CVE-2002-0721");
 script_bugtraq_id(5309, 5310, 5311, 5312, 5481, 5483, 5877, 5980);
 script_osvdb_id(
  10127,
  10131,
  10136,
  10137,
  10138,
  10139,
  10140,
  4577,
  4578,
  4776,
  4777,
  4778,
  4779,
  878
 );
 script_xref(name:"MSFT", value:"MS02-061");

 script_name(english:"MS02-061: Microsoft SQL Server Multiple Vulnerabilities (uncredentialed check)");
 script_summary(english:"Microsoft's SQL UDP Info Query");

 script_set_attribute(
  attribute:"synopsis",
  value:"The remote database server is affected by multiple buffer overflows."
 );
 script_set_attribute(attribute:"description", value:
"The remote MS SQL server is affected by several overflows that could
be exploited by an attacker to gain SYSTEM access on that host.

Note that a worm (sapphire) is exploiting these vulnerabilities in the
wild." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms02-061");
 script_set_attribute(
  attribute:"solution",
  value:
"Microsoft has released patches for SQL Server 7.0 and 2000 as well as
Microsoft Data Engine (MSDE) 1.0 and 2000."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS02-039 Microsoft SQL Server Resolution Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/01/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:data_engine");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Databases");

 script_dependencies("mssql_ping.nasl");
 script_require_keys("MSSQL/UDP/Ping");
 exit(0);
}

#
# The script code starts here
#


function sql_ping()
{
 local_var r, req, soc;

 req = raw_string(0x02);
 if(!get_udp_port_state(1434))exit(0);
 soc = open_sock_udp(1434);


 if(soc)
 {
	send(socket:soc, data:req);
	r  = recv(socket:soc, length:4096);
	close(soc);
	return(r);
 }
}



r = sql_ping();
if(strlen(r) > 0)
 {
  soc = open_sock_udp(1434);
  send(socket:soc, data:raw_string(0x0A));
  r = recv(socket:soc, length:1);
  if(strlen(r) > 0 && ord(r[0]) == 0x0A)security_hole(port:1434, proto:"udp");
 }
exit(0);



