#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(26917);
 script_version ("$Revision: 1.10 $");
 
 script_name(english:"Microsoft Windows SMB Registry : Nessus Cannot Access the Windows Registry");
 
 script_set_attribute(attribute:"synopsis", value:
"Nessus is not able to access the remote Windows Registry." );
 script_set_attribute(attribute:"description", value:
"It was not possible to connect to PIPE\winreg on the remote host.

If you intend to use Nessus to perform registry-based checks, the
registry checks will not work because the 'Remote Registry Access'
service (winreg) has been disabled on the remote host or can not be
connected to with the supplied credentials." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/04");
 script_cvs_date("$Date: 2011/03/27 01:19:44 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();
 
 script_summary(english:"Determines whether the remote registry is accessible");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_registry_access.nasl");
 script_require_keys("SMB/registry_not_accessible");
 exit(0);
}

#

port = get_kb_item("SMB/transport");
val = get_kb_item("SMB/registry_not_accessible");

if (val)
{
  reason = get_kb_item("SMB/registry_not_accessible/reason");
  if ( isnull(reason) )  security_note(port);
  else security_note(port:port, extra:'Could not connect to the registry because:\n' + reason);
}

