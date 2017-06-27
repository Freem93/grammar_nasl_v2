#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11561);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/01/12 17:12:47 $");
 script_cve_id("CVE-2003-1122");
 script_bugtraq_id(7476);
 script_osvdb_id(15656);
 script_xref(name:"CERT", value:"813737");

 script_name(english:"ScriptLogic $LOGS Share Remote Information Disclosure");
 script_summary(english:"Connects to LOG$");

 script_set_attribute(attribute:"synopsis", value:"Sensitive data may be accessed on the remote server.");
 script_set_attribute(attribute:"description", value:
"The remote host has an accessible LOGS$ share.

ScriptLogic creates this share to store the logs, but does not
properly set the permissions on it. As a result, anyone can use it to
read or modify, or possibily execute code.");
 script_set_attribute(attribute:"solution", value:
"Limit access to this share to the backup account and domain
administrator.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/04");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("audit.inc");


port = kb_smb_transport();
name = kb_smb_name();
if(!name)exit(0);


login = kb_smb_login();
pass = kb_smb_password();
dom = kb_smb_domain();







if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:dom, share:"LOGS$");
if ( r != 1 ) exit(1);

handle = FindFirstFile (pattern:"\*");
if ( ! isnull(handle) ) security_note(port);
NetUseDel();
