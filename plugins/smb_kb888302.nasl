#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16337);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2015/01/12 17:12:47 $");

 script_cve_id("CVE-2005-0051");
 script_bugtraq_id(12486);
 script_osvdb_id(13596);
 script_xref(name:"MSFT", value:"MS05-007");

 script_name(english:"MS05-007: Vulnerability in Windows Could Allow Information Disclosure (888302) (uncredentialed check)");
 script_summary(english:"Determines if hotfix 888302 has been installed");

 script_set_attribute(attribute:"synopsis", value:
"System information about the remote host can be obtained by an
anonymous user.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw that may allow an
attacker to cause it to disclose information over the use of a named
pipe through a NULL session.

An attacker may exploit this flaw to gain more knowledge about the
remote host.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms05-007");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_nativelanman.nasl");
 script_require_ports(139,445);
 exit(0);
}

#

include ("smb_func.inc");
include("audit.inc");

os = get_kb_item ("Host/OS/smb") ;

# 'Officially', only XP is affected.
if ( ! os || "Windows 5.1" >!< os ) exit(0);

port = int(get_kb_item("SMB/transport"));
if (!port) port = 445;

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
NetUseAdd (share:"IPC$");

if ( NetSessionEnum(level:SESSION_INFO_10) )
  security_warning(port);

NetUseDel ();

