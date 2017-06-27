#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11454);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2015/09/24 16:49:07 $");

 script_xref(name:"CERT-CC", value:"CA-2003-08");

 script_name(english:"Microsoft Windows Administrator Default Password Detection (W32/Deloder Worm Susceptibility)");
 script_summary(english:"Attempts to log into the remote host");

 script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable to the W32/Deloder worm.");
 script_set_attribute(attribute:"description", value:
"W32/Deloder is a worm that tries to connect to a remote share by using
a list of built-in administrator passwords. 

Nessus was able to connect to this host with one of these credentials. 
The worm W32/Deloder may use it to break into the remote host and upload
infected data in the remote shares.");
 script_set_attribute(attribute:"solution", value:"Change your administrator password to a strong one.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/24");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl", "smb_sid2user.nasl", "smb_sid2localuser.nasl", "snmp_lanman_users.nasl");
 script_exclude_keys("SMB/any_login", "global_settings/supplied_logins_only");
 script_require_keys("SMB/name");
 script_require_ports(139, 445);
 script_timeout(0);

 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("misc_func.inc");
include("global_settings.inc");

if (get_kb_item("SMB/any_login")) exit(0, "The remote host authenticates users as 'Guest'.");
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);


function log_in(login, pass)
{
 local_var soc, r;
 soc = open_sock_tcp(port);
 if (!soc) audit(AUDIT_SOCK_FAIL, port);

 session_init(socket:soc, hostname:kb_smb_name());
 r = NetUseAdd(login:login, password:pass, domain:NULL, share:"IPC$");
 NetUseDel();
 if ( r == 1 && session_is_guest() == 0 ) return TRUE;
 else
  return(FALSE);
}


login = string(get_kb_item("SMB/LocalUsers/0"));
if(!login)login = "administrator";

# https://discussions.nessus.org/message/9562#9562 -- Apple's Time Capsule accepts any login with a 
# blank password
if ( log_in(login:rand_str(length:8), pass:"")  ) exit(1, "The remote SMB server accept any login with a blank password");


passwords = make_list("", "0", "000000", "00000000", "007", "1",
		      "110", "111", "111111", "11111111", "12",
		      "121212", "123", "123123", "1234", "12345",
		      "123456", "1234567", "12345678", "123456789",
		      "1234qwer", "123abc", "123asd", "123qwe",
		      "2002", "2003", "2600", "54321", "654321",
		      "88888888", "Admin", "Internet", "Login",
		      "Password", "a", "aaa", "abc", "abc123", "abcd",
		      "admin", "admin123", "administrator", "alpha",
		      "asdf", "computer", "database", "enable", "foobar",
		      "god", "godblessyou", "home", "ihavenopass", "login",
		      "love", "mypass", "mypass123", "mypc", "mypc123",
		      "oracle", "owner", "pass", "passwd", "password",
		      "pat", "patrick", "pc", "pw", "pw123", "pwd", "qwer",
		      "root", "secret", "server", "sex", "super", "sybase",
		      "temp", "temp123", "test", "test123", "win", "xp",
		      "xxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		      "yxcv", "zxcv");


foreach p (passwords)
{
 if(log_in(login:login, pass:p))
 {
  if (report_verbosity > 0)
  {
    report = strcat('\nThe account \'', login, '\'/\'',p, '\' is valid.\n');

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
 }
}

audit(AUDIT_HOST_NOT, "affected");
