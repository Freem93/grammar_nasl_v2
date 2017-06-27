#
# This script was written by Douglas Minderhout <dminderhout@layer3com.com>
# This script is based uppon a script by Rui Bernardino <rbernardino@oni.pt>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - only attempt to login if the policy allows it (10/25/11 and 6/2015)
# - Revised plugin title, output formatting (9/2/09)
# - include global_settings.inc (6/2015)


include("compat.inc");

if (description)
{
  script_id(11327);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/09 22:45:48 $");

  script_name(english:"Nortel Baystack Default Password");
  script_summary(english:"Logs into the remote Nortel terminal server");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is reachable with known default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote switch has a weak password. This means that anyone who has
(downloaded) a user manual can telnet to it and gain administrative 
access.");
  script_set_attribute(attribute:"solution", value:
"Telnet to this switch and set passwords under 
'Console/Comm Port Configuration' for both read only and read write. 
Then, set the parameter 'Console Switch Password'
or 'Console Stack Password' to 'Required for TELNET' or
'Required for Both'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2003-2015 Douglas Minderhout");

  script_require_ports(23);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}



include('telnet_func.inc');
include("global_settings.inc");
function myrecv(socket, pattern) {
	while(1) {
		r = recv_line(socket:soc, length:1024);
		if(strlen(r) == 0) return(0);
		if(ereg(pattern:pattern, string:r)) return(r);
	}
}



#
# The script code starts here
#
port = 23;

if(get_port_state(port)) {

	if (supplied_logins_only) exit(0, "Policy is configured to prevent trying default user accounts");
	buf = get_telnet_banner(port:port);
	if ( ! buf || "Ctrl-Y" >!< buf ) exit(0);


	soc=open_sock_tcp(port);
	if(!soc)exit(0);
	buf=telnet_negotiate(socket:soc);
	#display(buf);
	# If we catch one of these, it's something else
	if("NetLogin:" >< buf)exit(0);
	if("Login:" >< buf)exit(0);
	# If we get Ctrl-Y in the response we're in business
	if ("Ctrl-Y" >< buf) {
		# Here we send it the Ctrl-y in HEX
		test = raw_string(0x19,0xF0);
		send(socket:soc, data:test);
		resp = recv(socket:soc, length:1024);
		#display(resp);
		if("P Configuration" >< resp) {
			# No password has been set
			e = "There is no password assigned to the remote Baystack switch.";
			security_hole(port:port, extra:e);
		} else {	 
			if ("asswor" >< resp ){
				# A password has been set, now we try some defaults
				test = string("secure\r");
         	send(socket:soc, data:test);
				resp = recv(socket:soc, length:1024);
				if("P Configuration" >< resp) {
					e = "The default password 'secure' is assigned to the remote Baystack switch.";
					security_hole(port:port, extra:e);
				} else {
					if ("asswor" >< resp ){
						# "secure' didn't work, let's try "user"
						test = string("user\r");
         			send(socket:soc, data:test);
						resp = recv(socket:soc, length:1024);
						if("P Configuration" >< resp) {
							e = "The default password 'user' is assigned to the remote Baystack switch.";
							security_hole(port:port, extra: e);
						}
					}
				}
			}
		}
	# The older switches do not do the Ctrl-Y thing, they just let you in
	} else {
		if ("P Configuration" >< buf) {
				e = 
"There is no password assigned to the remote Baystack switch. This switch
is most likely using a very old version of software. It would be best to 
contact Nortel for an upgrade.";
				security_hole(port:port, extra:e);
		}
	}
	close (soc);
} 
