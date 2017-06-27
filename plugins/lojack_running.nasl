#
# (C) Tenable Network Security, Inc.
#


if ( NASL_LEVEL < 3206 ) exit(0);


include("compat.inc");

if (description)
{
 script_id(40468);
 script_version("$Revision: 1.7 $");
 script_osvdb_id(56734);
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");

 script_name(english:"Absolute Software Computrace LoJack for Laptops Detection");
 script_summary(english:"Reads the tasklist");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running the Computrace LoJack theft-recovery
device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Computrace LoJack, a laptop theft-recovery
device.

Note that a flaw has been discovered in this product that might allow
an attacker to execute arbitrary code on the remote host. There is no
patch for this vulnerability yet.");
 script_set_attribute(attribute:"see_also", value:"http://blogs.zdnet.com/security/?p=3828");

 script_set_attribute(attribute:"solution", value:
"Make sure use of this software is in agreement with your
organization's security and acceptable use policies.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/03");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("wmi_process_on_port.nbin", "smb_hotfixes.nasl");
 script_require_keys("SMB/login", "SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(0);



kb = get_kb_item("Host/Windows/tasklist_svc");
if ( kb )
 process_running = egrep(pattern:"^rpcnet\.exe", string:kb, icase:TRUE);

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



winroot = hotfix_get_systemroot();
if (!winroot) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
exe   =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\rpcnet.exe", string:winroot);






if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


version = NULL;
fh = CreateFile(file:exe,
		desired_access:GENERIC_READ,
		file_attributes:FILE_ATTRIBUTE_NORMAL,
		share_mode:FILE_SHARE_READ,
		create_disposition:OPEN_EXISTING);
if (!isnull(fh))
{
  ret = GetFileVersion(handle:fh);
  if ( ! isnull(ret) )
  {
   version = string(ret[0], ".", ret[1], ".", ret[2], ".", ret[3]);
  }
  CloseFile(handle:fh);
}

NetUseDel();

if ( !isnull(version) )
{
 set_kb_item(name:"SMB/LoJack/Version", value:version);
 extra = '\nLoJack for Laptops version ' + version + ' is installed on the remote host.\n\n';
 if ( process_running ) extra += 'The process \'rpcnet.exe\' is running as :\n\n' + process_running;

 security_note(port:0, extra:extra);
}
