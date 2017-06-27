#
# This script was written by Rui Bernardino <rbernardino@oni.pt>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - only attempt to login if the policy allows it (10/25/11 and 6/2015)
# - Revised plugin title, output formatting (9/2/09)
# - include global_settings.inc
 

include("compat.inc");

if (description)
{
  script_id(10989);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/06/27 14:51:42 $");

  script_cve_id("CVE-1999-0508");
  script_osvdb_id(812);

  script_name(english:"Nortel/Bay Networks Default Password");
  script_summary(english:"Logs into the remote Nortel switch/router");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is reachable with known default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote switch/routers uses the default password.
This means that anyone who has (downloaded) a user manual can telnet
to it and gain administrative access.");
  script_set_attribute(attribute:"solution", value:
"Telnet this switch/router and change all passwords (check the manual
for default users).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2002-2016 Rui Bernardino");

  script_require_ports(23);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
 }
 
 #
 # The script code starts here
 #
 include('telnet_func.inc');
 include("global_settings.inc");

 port = 23;
 
 if(get_port_state(port)) {

	if (supplied_logins_only) exit(0, "Policy is configured to prevent trying default user accounts");
	banner = get_telnet_banner(port:port);
	if ( !banner || "Passport" >!< banner ) exit(0);
 
       # Although there are at least 11 (!?) default passwords to check, the passport will only allow
       # 3 attempts before closing down the telnet port for 60 seconds. Fortunately, nothing prevents
       # you to establish a new connection for each password attempt and then close it before the 3 attempts.
       
       user[0]="rwa";
       pass[0]="rwa";
       
       user[1]="rw";
       pass[1]="rw";
       
       user[2]="l3";
       pass[2]="l3";
       
       user[3]="l2";
       pass[3]="l2";
       
       user[4]="ro";
       pass[4]="ro";
       
       user[5]="l1";
       pass[5]="l1";
       
       user[6]="l4admin";
       pass[6]="l4admin";
       
       user[7]="slbadmin";
       pass[7]="slbadmin";
       
       user[8]="operator";
       pass[8]="operator";
       
       user[9]="l4oper";
       pass[9]="l4oper";
       
       user[10]="slbop";
       pass[10]="slbop";
       
       PASS=11;
       
       for(i=0;i<PASS;i=i+1) {
	       soc=open_sock_tcp(port);
	       if(!soc)exit(0);
	       buf=telnet_negotiate(socket:soc);
	       #display(buf);
	       if("NetLogin:" >< buf)exit(0);
	       if ( "Passport" >< buf ){
			       if ("Login:" >< buf) {
				       test = string(user[i],"\n",pass[i],"\n");
				       send(socket:soc, data:test);
				       resp = recv(socket:soc, length:1024);
				       #display(resp);
				       if(strlen(resp) &&
					  "Access failure" >!< resp &&
					  "Login" >!< resp &&
					  egrep(pattern:".*:[0-9]#", string:resp) ) {
					       e = string ("Password for user ",user[i]," is ",pass[i]);
					       security_hole(port:port, extra: e);
				       }
			       }
		       close (soc);
	       }
	        else exit(0);
       }
 }
