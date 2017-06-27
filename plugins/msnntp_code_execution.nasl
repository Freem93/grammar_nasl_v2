#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15465);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2014/07/11 21:44:07 $");

 script_cve_id("CVE-2004-0574");
 script_bugtraq_id(11379);
 script_osvdb_id(10697);
 script_xref(name:"MSFT", value:"MS04-036");

 script_name(english:"MS04-036: Microsoft NNTP Component Remote Overflow (883935) (uncredentialed check)");
 script_summary(english:"Checks the remote NNTP daemon version");

 script_set_attribute(attribute:"synopsis", value:"The remote NNTP server is susceptible to a buffer overflow attack.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft NNTP server that is
vulnerable to a buffer overflow issue. 

An attacker may exploit this flaw to execute arbitrary commands on the
remote host with the privileges of the NNTP server process." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms04-036");
 script_set_attribute(attribute:"solution", value:"Microsoft has released patches for Windows NT, 2000, and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/10/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencie("nntpserver_detect.nasl");
 script_require_ports("Services/nntp", 119);
 exit(0);
}

#
# The script code starts here
#



port = get_kb_item("Services/nntp");
if(!port)port = 119;
if (! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
banner = recv_line(socket:soc, length:8192);
if ( ! banner ) exit(0);
close(soc);

if ( "200 NNTP Service" >< banner )
{
 version = egrep(string:banner, pattern:"^200 NNTP Service");
 version = ereg_replace(string:version, pattern:"^200 NNTP Service .* Version: (.*) ", replace:"\1");
 ver = split(version, sep:".", keep:0);
 if ( int(ver[0]) == 6 )
 {
  if ( int(ver[1]) == 0 && ( int(ver[2]) < 3790 || ( int(ver[2]) == 3790 && int(ver[3]) < 206 ) ) ) security_hole(port);
 }

 if ( int(ver[0]) == 5 )
 {
  if ( int(ver[1]) == 0 && ( int(ver[2]) < 2195 || ( int(ver[2]) == 2195 && int(ver[3]) < 6972 ) ) ) security_hole(port);
 }
}
