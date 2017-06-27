#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(26920);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2012/02/29 15:28:59 $");

 script_cve_id("CVE-1999-0519", "CVE-1999-0520", "CVE-2002-1117");
 script_bugtraq_id(494);
 script_osvdb_id(299, 8230);

 script_name(english:"Microsoft Windows SMB NULL Session Authentication");
 script_summary(english:"Attempts to log into the remote host using a NULL session");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote Windows host with a NULL
session.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Microsoft Windows. It is possible to log into it
using a NULL session (i.e., with no login or password).

Depending on the configuration, it may be possible for an unauthenticated,
remote attacker to leverage this issue to get information about the remote
host.");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/q143474/");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/q246261/");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/library/cc785969(WS.10).aspx");
 script_set_attribute(attribute:"solution", value:
"Apply the following registry changes per the referenced Technet 
advisories :

Set : 
 - HKLM\SYSTEM\CurrentControlSet\Control\LSA\RestrictAnonymous=1
 - HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\restrictnullsessaccess=1

Remove BROWSER from :
 - HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\NullSessionPipes

Reboot once the registry changes are complete.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/04");
 script_set_attribute(attribute:"vuln_publication_date", value:"1999/07/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_login.nasl");
 script_require_keys("SMB/null_session_enabled");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/null_session_enabled");

port = kb_smb_transport();
# we need the  netbios name of the host
name = kb_smb_name();
if(!name)exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init (socket:soc,hostname:name);

ret = NetUseAdd (login:"", password:"", domain:"", share:"IPC$");

if (ret != 1)
{
  close(soc);
  exit(0);
}

fid = bind_pipe (pipe:"\browser", uuid:"6bffd098-a112-3610-9833-012892020162", vers:0);
if (!isnull(fid))
  security_warning(port:port, extra:"It was possible to bind to the \browser pipe");

NetUseDel ();
