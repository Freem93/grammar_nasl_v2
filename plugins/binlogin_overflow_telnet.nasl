#
# (C) Tenable Network Security, Inc.
#

#
# Sun's patch makes /bin/login exits when it receives too many arguments,
# hence making the detection of the flaw difficult. Our logic is the
# following :
#
# Username: "nessus" -> should not crash
# Username: "nessus A=B..... x 61"  -> should not crash
# Username: "nessus A=B..... x 100" -> should crash
#

include("compat.inc");

if (description)
{
   script_id(10827);
   script_version("$Revision: 1.35 $");
   script_cvs_date("$Date: 2016/04/13 15:25:22 $");

   script_cve_id("CVE-2001-0797");
   script_bugtraq_id(3681, 7481);
   script_osvdb_id(690);
   script_xref(name:"CERT-CC", value:"CA-2001-34");

   script_name(english:"SysV /bin/login Environment Remote Overflow (telnet check)");
   script_summary(english:"Attempts to overflow /bin/login");
 
   script_set_attribute(attribute:"synopsis", value:"It is possible to execute arbitrary code on the remote host.");
   script_set_attribute(attribute:"description", value:
"The remote /bin/login seems to crash when it receives too many
environment variables. This is likely due to a buffer overflow
vulnerability which might allow an attacker to execute arbitrary
code on the remote host.");
   script_set_attribute(attribute:"solution", value:"Apply the patch from your vendor or read the CERT advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
   script_set_attribute(attribute:"metasploit_name", value:'Solaris in.telnetd TTYPROMPT Buffer Overflow');
   script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
   script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
   script_set_attribute(attribute:"canvas_package", value:'CANVAS');

   script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/12");
   script_set_attribute(attribute:"plugin_publication_date", value:"2001/12/15");

   script_set_attribute(attribute:"plugin_type", value:"remote");
   script_end_attributes();
 
   script_category(ACT_DESTRUCTIVE_ATTACK);
   script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
   script_family(english:"Gain a shell remotely");
   script_dependencie("telnetserver_detect_type_nd_version.nasl");
   script_require_ports("Services/telnet", 23);
   exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include('telnet_func.inc');

login = rand_str(length:6);

port = get_kb_item("Services/telnet");
if(!port) port = 23;
if (!get_port_state(port)) exit(0, "Port "+port+" is closed.");

function login(env, try)
{
  local_var	i, soc, r, buffer;

  # if (try <= 0) try = 1;
  for (i = 0; i < try; i ++)
  {
    sleep(i);
    soc = open_sock_tcp(port);
    if (soc) break;
  }

   if (soc)
   {

 buffer = telnet_negotiate(socket:soc);
 send(socket:soc, data:string(login, " ", env, "\r\n"));
 r = recv(socket:soc, length:4096);
 close(soc);
 if("word:" >< r)
  {
	return(1);
  }
 }
 return(0);
}



if(login(env:"", try: 1))
{
 my_env = crap(data:"A=B ", length:244);
 res = login(env:my_env);
 if(res)
 {
  my_env = crap(data:"A=B ", length:400);
  res = login(env:my_env, try: 4);
  if(!res)security_hole(port);
 }
}
