#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10828);
  script_version("$Revision: 1.34 $");
  script_cvs_date("$Date: 2016/04/13 15:25:22 $");

  script_cve_id("CVE-2001-0797");
  script_bugtraq_id(3681);
  script_osvdb_id(691);
  script_xref(name:"CERT-CC", value:"CA-2001-34");

  script_name(english:"SysV /bin/login Environment Remote Overflow (rlogin)");
  script_summary(english:"Attempts to overflow /bin/login");

  script_set_attribute(attribute:"synopsis", value:"It is possible to execute arbitrary code on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote /bin/login seems to crash when it receives too many
environment variables. This is likely due to a buffer overflow
vulnerability which might allow an attacker to execute arbitrary code
on the remote host.");
  script_set_attribute(attribute:"solution", value:"Apply the patch from your vendor (or read the CERT advisory).");
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

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");

  script_dependencie("find_service1.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/rlogin", 513);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


login = rand_str(length:6);

port = get_kb_item("Services/rlogin");
if(!port)port = 513;


global_var port;

function rlogin(env)
{
 local_var soc, s1, s2, a;

if(get_port_state(port))
{
 soc = open_priv_sock_tcp(dport:port);
 if(soc)
 {
  s1 = raw_string(0);
  s2 = string(login, s1, s1);
  send(socket:soc, data:s1);
  send(socket:soc, data:s2);

  a = recv(socket:soc, length:1, min:1);


  if(!strlen(a)){
  	return(0);
	}
  if(!(ord(a[0]) == 0)){
  	return(0);
	}
  send(socket:soc, data:s1);
  a = recv(socket:soc, length:1024, min:1);
  if("ogin:" >< a)
  {
    send(socket:soc, data:string(env, "\r\n"));
    a = recv(socket:soc, length:4096);
    a = recv(socket:soc, length:4096);
    if("word:" >< a)
    {
     close(soc);
     return(1);
    }
   }
   close(soc);
  }
  else return(0);
 }
 return(0);
}


if(rlogin(env:login))
{
res = rlogin(env:string(login, " ", crap(data:"A=B ", length:244)));
if(res)
 {
  res = rlogin(env:string(login, " ", crap(data:"A=B ", length:400)));
  if(!res)security_hole(port);
 }
}
