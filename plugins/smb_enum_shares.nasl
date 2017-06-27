#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10395);
 script_version("$Revision: 1.44 $");
 script_cvs_date("$Date: 2015/01/12 17:12:47 $");

 script_name(english:"Microsoft Windows SMB Shares Enumeration");
 script_summary(english:"Gets the list of remote shares");

 script_set_attribute(attribute:"synopsis", value:"It is possible to enumerate remote network shares.");
 script_set_attribute(attribute:"description", value:
"By connecting to the remote host, Nessus was able to enumerate the
network share names.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl","smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");

if (thorough_tests) max_shares = 10000;
else max_shares = 200;

login = kb_smb_login();
pass = kb_smb_password();
dom = kb_smb_domain();
port = kb_smb_transport();

if ( ! login )
{
 login = pass = dom = NULL;
 if ( !supplied_logins_only && get_kb_item("SMB/any_login") )
 {
   login = "Nessus" + rand();
   pass = "Nessus" + rand();
 }
}

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, 'IPC$');
}

shares = NetShareEnum (level:SHARE_INFO_0);
if ( isnull(shares) ) shares = NetShareEnum (level:SHARE_INFO_1);
NetUseDel ();

if ( ! isnull(shares) )
  {
    res = NULL;
    nshares = 0;
    foreach share (shares)
    {
      nshares++;
      if (nshares <= max_shares)
      {
        set_kb_item(name:"SMB/shares", value:share);
        res = res + '  - ' + share + '\n';
      }
    }

   if ( login ) login = "when logged in as " + login;
   if ( nshares != 0 )
   {
     if (nshares <= max_shares)
     {
     report = string(
   "\n",
   "Here are the SMB shares available on the remote host ", login, ":\n",
   "\n",
   res
  );
    }
 else
   {
    report = string(
   "\n",
   nshares, " SMB shares are available on the remote host ", login, ".\nHere are the first ", max_shares, " :\n",
   "\n",
   res
   );
   }
  security_note(port:port, extra:report);
  }
 }
