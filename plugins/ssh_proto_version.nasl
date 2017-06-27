#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10881);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2013/10/21 00:06:38 $");

 script_name(english:"SSH Protocol Versions Supported");
 script_summary(english:"Negotiate SSHd connections");

 script_set_attribute(attribute:"synopsis", value:
"A SSH server is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"This plugin determines the versions of the SSH protocol supported by
the remote SSH daemon.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/06");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");


function test_version(version, port)
{
 local_var soc, r, str;

 soc = open_sock_tcp(port);
 if (!soc) audit(AUDIT_SOCK_FAIL, port);

 r = recv_line(socket:soc, length:255);
 if (!r) audit(AUDIT_NO_BANNER, port);

if(!ereg(pattern:"^SSH-.*", string:r)){
	close(soc);
	return(0);
	}

str = string("SSH-", version, "-", kb_ssh_client_ver(), "\n");
send(socket:soc, data:str);
r = recv(socket:soc, length:255, min:1, timeout:10);
close(soc);
sleep(1);
if(!strlen(r))return(0);
if(ereg(pattern:"^Protocol.*version", string:r))return(0);
else if ("ssh version is too old" >< r) return(0);
else return(1);
}





function sshv1_recv(socket)
{
 local_var len, head, data;

 head  = recv(socket:socket, length:4, min:4);
 if ( strlen(head) < 4 ) return NULL;

 len = ord(head[2]) * 256 + ord(head[3]);
 data = recv(socket:socket, length:len, min:len);
 return head + data;
}

function ssh2_get_fingerprint(port)
{
 local_var soc,key, fingerprint, fg, i;

 _ssh_socket = open_sock_tcp(port);
 if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

 if ( ! supplied_logins_only ) ssh_login ();
 close(_ssh_socket);

 key = get_server_public_key();

 if (key != NULL)
 {
  fingerprint = hexstr(MD5(key));
  fg = "";
  for ( i = 0 ; i < strlen(fingerprint) ; i += 2 )
  {
   fg += substr(fingerprint, i, i + 1);
   if ( i + 2 < strlen(fingerprint) ) fg += ":";
  }

  return fg;
 }
 return NULL;
}

function ssh1_get_fingerprint(port)
{
 local_var soc,key, key_len, key_len_str, blob, fingerprint, fg, i, idx, buf;

 soc = open_sock_tcp(port);
 if (!soc) audit(AUDIT_SOCK_FAIL, port);

 buf = recv_line(socket:soc, length:4096);
 send(socket:soc, data:'SSH-1.5-' + kb_ssh_client_ver() + '\n');

  blob = sshv1_recv(socket:soc);
  close(soc);
  if ( blob != NULL && "Protocol" >!< blob && strlen(blob) >= (132 + 127) )
  {
  idx = stridx(hexstr(blob), "e8dc4c7f1b53b99ff6f89bc7bf0448cf587d667");
  key_len_str = substr(blob, 130,131);
  key_len = ord(key_len_str[0]) * 256 + ord(key_len_str[1]);
  key = substr(blob, 132, 132 + 127 ) + raw_string(0x23);
  fingerprint = hexstr(MD5(key));
  fg = "";
  for ( i = 0 ; i < strlen(fingerprint) ; i += 2 )
  {
   fg += substr(fingerprint, i, i + 1);
   if ( i + 2 < strlen(fingerprint) ) fg += ":";
  }
  return fg;
 }
 return NULL;
}

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

v = 0;

vers_1_33 = 0;
vers_1_5  = 0;
vers_1_99 = 0;
vers_2_0  = 0;

# Some SSHd implementations reply to anything.
if(test_version(version:"9.9", port:port))
{
 exit(0, "The SSH service listening on port "+port+" claims to support a nonsensical SSH protocol version.");
}

if(test_version(version:"1.33", port:port))
	{
	v = 1;
	vers_1_33 = 1;
	}

if(test_version(version:"1.5", port:port))
	{
	v = 1;
	vers_1_5 = 1;
	}

if(test_version(version:"1.99", port:port))
	{
	v = 1;
	vers_1_99 = 1;
	}

if(test_version(version:"2.0", port:port))
	{
	v = 1;
	vers_2_0 = 1;
	}



report = string("The remote SSH daemon supports the following versions of the\n",
"SSH protocol :\n\n");

if(vers_1_33)report = string(report, "  - 1.33\n");
if(vers_1_5){
	report = string(report, "  - 1.5\n");
	fg1 = ssh1_get_fingerprint(port:port);
	}
if(vers_1_99)report = string(report, "  - 1.99\n");
if(vers_2_0) {
	report = string(report, "  - 2.0\n");
	fg2 = ssh2_get_fingerprint(port:port);
	}

if ( vers_1_33 || vers_1_5 )
{
 set_kb_item(name:"SSH/" + port + "/v1_supported", value:TRUE);
}

if ( fg1 || fg2 ) report += '\n\n';
if ( fg1 ) report += "SSHv1 host key fingerprint : " + fg1 + '\n';
if ( fg2 ) report += "SSHv2 host key fingerprint : " + fg2 + '\n';


if (v)
 security_note(port:port, extra:report);
