#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11105);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
 script_cve_id("CVE-2001-0960");
 script_bugtraq_id(3343);
 script_osvdb_id(5482);

 script_name(english:"CA BrightStor ARCserve Backup Agent Credential Disclosure");
 script_summary(english:"Connects to ARCSERVE$");

 script_set_attribute(attribute:"synopsis", value:"Backup share can be accessed without authentication.");
 script_set_attribute(attribute:"description", value:
"The remote host has an accessible ARCSERVE$ share.

Several versions of ARCserve store the backup agent username and
password in a plaintext file on this share.

An attacker may use this flaw to obtain the password file of the
remote backup agent, and use it to gain privileges on this host.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Sep/171");
 script_set_attribute(attribute:"solution", value:
"Limit access to this share to the backup account and domain
administrator.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/22");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include ("smb_func.inc");
include("audit.inc");

port = kb_smb_transport();
if(!port) port = 139;

name = kb_smb_name();
if(!name)exit(0);

#if(!get_port_state(port))exit(0);

#soc = open_sock_tcp (port);
#if (!soc) exit (0);

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


r = NetUseAdd(login:NULL, password:NULL, domain:NULL, share:"ARCSERVE$");
if ( r != 1 )
{
 exit(1);
}

# Open current directory in read mode
handle = CreateFile (file:"", desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_DIRECTORY,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull (handle) )
{
 CloseFile(handle:handle);
 security_hole (port);
}

NetUseDel ();
