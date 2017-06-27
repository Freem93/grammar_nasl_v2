#
# (C) Tenable Network Security, Inc.
#

#
# Requested by Michael Richardson
#


include("compat.inc");

if (description)
{
 script_id(17651);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2015/01/12 17:12:48 $");

 script_name(english:"Microsoft Windows SMB : Obtains the Password Policy");
 script_summary(english:"Check password policy");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to retrieve the remote host's password policy using the
supplied credentials.");
 script_set_attribute(attribute:"description", value:
"Using the supplied credentials it was possible to extract the password
policy for the remote Windows host. The password policy must conform
to the Informational System Policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/30");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : User management");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("smb_func.inc");

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) audit(AUDIT_SHARE_FAIL, 'IPC$');

modals = NetUserGetModals(level:1);
if (!isnull(modals))
{
 policy = string("The following password policy is defined on the remote host:\n\n");
 policy += string("Minimum password len: ", modals[0], "\n");
 policy += string("Password history len: ", modals[1], "\n");
 if ( modals[3] < 0 )
 	policy += string("Maximum password age (d): No limit\n");
 else
 	policy += string("Maximum password age (d): ", modals[3]/(3600*24), "\n");

 # Native version of NetUserGetModals() doesn't return
 # password complexity info
 if(! isnull(modals[2]))
 {
   if ( modals[2] == 0)
          policy += string("Password must meet complexity requirements: Disabled\n");
   else
          policy += string("Password must meet complexity requirements: Enabled\n");
 }
 policy += string("Minimum password age (d): ", modals[4]/(3600*24), "\n");

 if ( modals[5] < 0 )
 	policy += string("Forced logoff time (s): Not set\n");
 else
 	policy += string("Forced logoff time (s): ", modals[5], "\n");

 modals2 = NetUserGetModals (level:3);
 if (!isnull (modals2))
 {
  if ( modals2[0] < 0 )
  	policy += string("Locked account time (s): Not set\n");
  else
  	policy += string("Locked account time (s): ", modals2[0], "\n");

  if ( modals2[1] < 0 )
  	policy += string("Time between failed logon (s): Not set\n");
  else
  	policy += string("Time between failed logon (s): ", modals2[1], "\n");

  policy += string("Number of invalid logon before locked out (s): ", modals2[2], "\n");
 }

 security_note (port:port, extra:policy);
}

NetUseDel();
