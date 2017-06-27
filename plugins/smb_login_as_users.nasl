#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10404);
 script_version("$Revision: 1.58 $");
 script_cvs_date("$Date: 2016/04/05 21:24:24 $");

 script_cve_id("CVE-1999-0504", "CVE-1999-0506");
 script_osvdb_id(3106, 10050);

 script_name(english:"Microsoft Windows SMB Guessable User Credentials");
 script_summary(english:"Attempts to log into the remote host");

 script_set_attribute(attribute:"synopsis", value:"Credentials for the remote Windows host can be discovered.");
 script_set_attribute(attribute:"description", value:
"This script attempts to log into the remote host using several login /
password combinations.");
 script_set_attribute(attribute:"solution", value:"Have the affected user(s) choose a good password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows Authenticated Powershell Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

script_set_attribute(attribute:"vuln_publication_date", value:"1999/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl", "smb_sid2user.nasl", "smb_sid2localuser.nasl",
 		     "snmp_lanman_users.nasl");
 script_exclude_keys("SMB/any_login", "global_settings/supplied_logins_only");
 script_require_keys("SMB/name");
 script_require_ports(139, 445);
 script_timeout(0);

 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("global_settings.inc");

 if ( safe_checks() ) exit(0, "This plugin requires safe checks to be disabled.");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
if (get_kb_item("SMB/any_login")) exit(0, "The remote host authenticates users as 'Guest'.");

global_var	port;

function log_in(login, pass, domain)
{
 local_var r, soc;

 soc = open_sock_tcp(port);
 if (!soc) audit(AUDIT_SOCK_FAIL, port);

 session_init(socket:soc, hostname:kb_smb_name());
 r = NetUseAdd(login:login, password:pass, domain:domain);
 if ( r == 1 && session_is_guest() ) r = 0;
 NetUseDel();

 if (r == 1)
   return TRUE;

 return(FALSE);
}


#----------------------------------------------------------------#
# 			  main()                                 #
#----------------------------------------------------------------#

port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

finished = 0;
count = 1;
vuln = "";

okcount = 1;
login = kb_smb_login();
pass  = kb_smb_password();
dom = kb_smb_domain();

if ( login ) set_kb_item(name:string("SMB/ValidUsers/0/Login"), value:login);
if ( pass ) set_kb_item(name:string("/tmp/SMB/ValidUsers/0/Password"), value:pass);

current = "SMB/Users";

if(log_in(login:"nessus"+rand(), pass:"nessus"+rand(), domain:dom))exit(0);


while(!finished)
{
 login = string(get_kb_item(string(current, count)));
 if(!login){
  	if(current == "SMB/LocalUsers/")
	  {
   		finished = 1;
	  }
	else {
	  current = "SMB/LocalUsers/";
	  count = 0;
	}
 }
 else
 {
  if(log_in(login:login, pass:"", domain:dom))
  {
   vuln = vuln + string("  - the user '", login, "' has NO password !\n");
   a = string("SMB/ValidUsers/", okcount, "/Login");
   b = string("/tmp/SMB/ValidUsers/", okcount, "/Password");
   if ( login ) set_kb_item(name:a, value:login);
   #set_kb_item(name:b, value:"");
   okcount = okcount + 1;
  }
  else if(log_in(login:login, pass:login, domain:dom))
  {
   vuln = vuln + string("  - the password for '", login, "' is '", login, "' !\n");
   a = string("SMB/ValidUsers/", okcount, "/Login");
   b = string("/tmp/SMB/ValidUsers/", okcount, "/Password");
   if ( login )
   {
    set_kb_item(name:a, value:login);
    set_kb_item(name:b, value:login);
   }
   okcount = okcount + 1;
  }
 }
 count = count + 1;
}

if (strlen(vuln))
{
  if (report_verbosity > 0) security_hole(port:port, extra:vuln);
  else security_hole(port);
}
else audit(AUDIT_HOST_NOT, "affected");
