#TRUSTED 7a37dba948eea95dc8750224f36b656949074fe83035f639b7904c51c14447992c31d6f69caa7b73335f1ba51a3ec947c865f5cf7783e27d2d439262d4afbf3d5ee80c24585ff64a0218d852a97167899cd4d0a3ab0684b2349ce143e7a18d2867a74dffe0bf9417d08ed0fb68f0f17620646af2a1533315da6ec0f69ae053bd6cd097b4828286005cac5ec05ba893b46850c8e42c7068828ae3ea58ba4bdf91ec77f77cbb219b1a378650e3ee5e51e5680b1b6327435377b7684182abd66c60c804d9e580a03b66b7a5dce71323308577d841f398af77996b275cbd6aa15167ac26020b989b76368765c183a25a43d9644fa3def41b036de7fbd8ceafd385fe1b5b2908b47bab3e040ec09fb1ae10cd62ec6d7d180a10787df3673d0c07d133e19749a55a5211fb5c2906424736607a86142979fc49d51db802a91d4bea2ad518d2ec4dbf94d9839a989cf02fe8828e043b7e07cdf23cd772d4440351f7e951c082f657bd4e120ec381534ecbef5a9bf28e0459c1fd0d966085ee164947708f75aa8e4509d8aec1c67c4072eeaff0657352f5d93c2a9e8d606ae9618be38da245162ce973506f298701e0b8a88c42ed8760154f702aca1b257f61d30099d460bf11740de343e42922cb8d0347ae26937fce3d3f06fd9fcbaf614e342d40ebdc7d143838e705114149fb1e35f640fd8407d564da1ea414cdda68070525dab8d4
#
# This script was written by Javier Fernandez-Sanguino
# based on a script written by Renaud Deraison <deraison@cvs.nessus.org>
# with contributions by Gareth M Phillips <gareth@sensepost.com> (additional logins and passwords)
#
# GPLv2
#
# TODO:
# - dump the device configuration to the knowledge base (requires
#   'enable' access being possible)
# - store the CISCO IOS release in the KB so that other plugins (in the Registered
#   feed) could use the functions in cisco_func.inc to determine if the system is
#   vulnerable as is currently done through SNMP (all the CSCXXXX.nasl stuff)
# - store the user/password combination in the KB and have another plugin test
#   for common combinations that lead to 'enable' mode.
#
# Changes by Tenable:
# - Coding changes regarding Cisco IOS XR/XE, along with some minor
#   tweaks in description block, were done (2017/01/13).

include("compat.inc");

if (description)
{
  script_id(23938);
  script_version("1.32");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/13");

  script_cve_id("CVE-1999-0508");
  script_osvdb_id(625);

  script_name(english:"Cisco Device Default Password");
  script_summary(english:"Checks for a default password.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device has a default factory password set.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco router has a default password set. A remote,
unauthenticated attacker can exploit this to gain administrative
access.");
  script_set_attribute(attribute:"solution", value:
"Change the default password via the command 'enable secret'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Javier Fernandez-Sanguino and Renaud Deraison");

  script_dependencie("find_service2.nasl", "ssh_get_info.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("telnet_func.inc");
include("ssh_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

global_var ssh_port, telnet_checked, telnet_port, ssh_found, telnet_found;

ssh_found = FALSE;
telnet_found = FALSE;

# Function to connect to a Cisco system through telnet, send
# a password

function check_cisco_telnet(login, password, port)
{
 local_var msg, r, r2, soc, report, pass_only;
 local_var i, info, line, ver;

 pass_only = TRUE;
 soc = open_sock_tcp(port);
 if ( ! soc )
 	{
	  telnet_port = 0;
	  return(0);
	}
 msg = telnet_negotiate(socket:soc, pattern:"(ogin:|asscode:|assword:)");
 if(strlen(msg))
 {
  # The Cisco device might be using an AAA access model
  # or have configured users:
  if ( stridx(msg, "sername:") != -1 || stridx(msg, "ogin:") != -1  )  {
    send(socket:soc, data:login + '\r\n');
    msg=recv_until(socket:soc, pattern:"(assword:|asscode:)");
    pass_only = FALSE;
  }

  # Device can answer back with {P,p}assword or {P,p}asscode
  # if we don't get it then fail and close
  if ( strlen(msg) == 0 || (stridx(msg, "assword:") == -1 && stridx(msg, "asscode:") == -1)  )  {
    close(soc);
    return(0);
  }

  send(socket:soc, data:password + '\r\n');
  r = recv(socket:soc, length:4096);

  # TODO: could check for Cisco's prompt here, it is typically
  # the device name followed by '>'
  # But the actual regexp is quite complex, from Net-Telnet-Cisco:
  #  '/(?m:^[\r\b]?[\w.-]+\s?(?:\(config[^\)]*\))?\s?[\$\#>]\s?(?:\(enable\))?\s*$)/')

  # Send a 'show ver', most users (regardless of privilege level)
  # should be able to do this
  send(socket:soc, data:'show ver\r\n');
  r = recv_until(socket:soc, pattern:"(Cisco (Internetwork Operating System|IOS|Adaptive Security Appliance) Software|assword:|asscode:|ogin:|% Bad password|% Login invalid)");
  # TODO: This is probably not generic enough. Some Cisco devices don't
  # use IOS but CatOS for example

  # TODO: It might want to change the report so it tells which user / passwords
  # have been found
  if (
     strlen(r) &&
     (
       "Cisco Internetwork Operating System Software" >< r ||
       "Cisco IOS Software" >< r ||
       "Cisco IOS XR Software" >< r ||
       "Cisco IOS XE Software" >< r ||
       "Cisco Adaptive Security Appliance Software" >< r
     )
  )
  {
    r2 = recv_until(socket:soc, pattern:'^System image file is "[^"]+"');
    if (strlen(r2)) r = strstr(r, "Cisco") + chomp(r2) + '\n' + '(truncated)';

    ver = egrep(pattern:"^.*IOS.*Version [0-9.]+(?:\(.*\))?.*", string:r);
    if (ver) {
        if ( !get_kb_item("Host/Cisco/show_ver" ) )
  		set_kb_item(name:"Host/Cisco/show_ver", value:ereg_replace(string:ver, pattern:".*(Cisco.*)", replace:"\1"));
	info = '\n  ' + chomp(ver);
    }
    else
    {
      info = '';
      i = 0;
      foreach line (split(r, keep:FALSE))
      {
        if (++i >= 5) break;
        info += '\n  ' + line;
      }
    }
    telnet_found = TRUE;

    report =
      '\n' + 'It was possible to log into the remote Cisco device via Telnet' +
      '\n' + 'using the following credentials :' +
      '\n';
    if (!pass_only) {
      report +=
        '\n' + '  User     : ' + login;
    }
    report +=
      '\n' + '  Password : ' + password +
      '\n' +
      '\n' + 'and to run the \'show ver\' command, which returned in part :'+
      '\n' +
      info + '\n';
    security_hole(port:port, extra:report);
  }

# TODO: it could also try 'enable' here and see if it's capable
# of accessing the privilege mode with the same password, or do it
# in a separate module

  close(soc);

 }
}

# Functions modified from the code available from default_accounts.inc
# (which is biased to UNIX)
function check_cisco_account(login, password)
{
 local_var port, ret, banner, soc, res, report;
 local_var buf, i, info, line, ver;

 if (ssh_port && get_port_state(ssh_port))
 {
  # Prefer login thru SSH rather than telnet
   _ssh_socket= open_sock_tcp(ssh_port);
   if ( _ssh_socket)
   {
   ret = ssh_login(login:login, password:password);
   if (ret == 0) buf = ssh_cmd(cmd:"show ver", nosh:TRUE, nosudo:TRUE, cisco:TRUE);
   else buf = "";
   close(_ssh_socket);
   if (
     buf &&
     (
       "Cisco Internetwork Operating System Software" >< buf ||
       "Cisco IOS Software" >< buf ||
       "Cisco IOS XR Software" >< buf ||
       "Cisco IOS XE Software" >< buf ||
       "Cisco Adaptive Security Appliance Software" >< buf
     )
   )
   {
     ver = egrep(pattern:"^.*IOS.*Version [0-9.]+(?:\(.*\))?.*", string:buf);
     if (ver) {
	info = '\n  ' + chomp(ver);
    	if ( !get_kb_item("Host/Cisco/show_ver" ) )
		set_kb_item(name:"Host/Cisco/show_ver", value:ereg_replace(string:ver, pattern:".*(Cisco.*)", replace:"\1"));
	}
     else
     {
       info = '';
       i = 0;
       foreach line (split(buf, keep:FALSE))
       {
         if (++i >= 5) break;
         info += '\n  ' + line;
       }
     }
     ssh_found = TRUE;

     report =
       '\n' + 'It was possible to log into the remote Cisco device via SSH' +
       '\n' + 'using the following credentials :' +
       '\n' +
       '\n' + '  User     : ' + login +
       '\n' + '  Password : ' + password +
       '\n' +
       '\n' + 'and to run the \'show ver\' command, which returned in part :'+
       '\n' +
       info + '\n';
     security_hole(port:ssh_port, extra:report);
   }
   }
   else
     ssh_port = 0;
 }

 if(telnet_port && get_port_state(telnet_port))
 {
  if ( isnull(password) ) password = "";
  if ( ! telnet_checked )
  {
  banner = get_telnet_banner(port:telnet_port);
  if ( banner == NULL ) { telnet_port = 0 ; return 0; }
  # Check for banner, covers the case of Cisco telnet as well as the case
  # of a console server to a Cisco port
  # Note: banners of cisco systems are not necessarily set, so this
  # might lead to false negatives !
  if ( stridx(banner,"User Access Verification") == -1 && stridx(banner,"assword:") == -1)
    {
     telnet_port = 0;
     return(0);
    }
   telnet_checked ++;
  }

  check_cisco_telnet(login:login, password:password, port:telnet_port);
 }
 if (ssh_found || telnet_found) exit(0);
 return(0);
}

ssh_port = get_kb_item("Services/ssh");
if ( ! ssh_port ) ssh_port = 22;


telnet_port = get_kb_item("Services/telnet");
if ( ! telnet_port ) telnet_port = 23;
telnet_checked = 0;

check_cisco_account(login:"cisco", password:"cisco");
check_cisco_account(login:"Cisco", password:"Cisco");
check_cisco_account(login:"", password:"");
if ( safe_checks() == 0 )
{
 check_cisco_account(login:"cisco", password:"");
 check_cisco_account(login:"admin", password:"cisco");
 check_cisco_account(login:"admin", password:"diamond");
 check_cisco_account(login:"admin", password:"admin");
 check_cisco_account(login:"admin", password:"system");
 check_cisco_account(login:"monitor", password:"monitor");
}
