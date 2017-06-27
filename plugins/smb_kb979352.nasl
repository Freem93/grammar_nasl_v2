#
#  (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2010/10/19.  Use smb_nt_ms10-002.nasl (plugin ID 44110) instead



include("compat.inc");

if (description)
{
  script_id(44060);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2011/03/07 01:17:52 $");
 
  script_name(english:"Internet Explorer < 8.0");
  script_summary(english:"Checks Internet Explorer version."); 

  script_set_attribute(attribute:"synopsis", value:
"A version of Internet Explorer before 8.0 is installed on the remote host."
  );
  script_set_attribute(attribute:"description", value:
"A version of Internet Explorer (IE) earlier than 8.0 is installed on
the remote host.  IE 8.0 by default enables Data Execution Protection
(DEP), which helps mitigate attacks against it. 

For this reason, Microsoft recommends that users upgrade to that
version for better security.

PLEASE NOTE: This plugin was disabled on 2010/10/19.  Use
smb_nt_ms10-002.nasl (plugin ID 44110) instead."
  );
  script_set_attribute(attribute:"see_also", value:"http://blogs.technet.com/msrc/archive/2010/01/14/security-advisory-979352.aspx");
  script_set_attribute(attribute:"solution", value:"Upgrade to Internet Explorer 8." );
  script_set_attribute(attribute:"risk_factor", value: "Medium");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/19");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/IE/Version");
  script_require_ports(139, 445);
  exit(0);
}

# Deprecated
exit(0);

include("global_settings.inc");
include("smb_func.inc");

port = kb_smb_transport();

# Check for Internet Explorer version.
version = get_kb_item("SMB/IE/Version");
if (!version) exit(1, "The 'SMB/IE/Version' KB item is missing.");

os = get_kb_item("SMB/WindowsVersion");
if (os && "5.0" >< os) exit(0, "IE 8 is not available for Windows 2000.");

v = split(version, sep:".", keep:FALSE);
if ( int(v[0]) > 0 && int(v[0]) < 8 )
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      "Internet Explorer version " + version + " is installed on the remote host." + '\n';
     security_warning(port:port, extra:report);
  }  	
  else security_warning(port);

  exit(0); 
}
else exit(0, "Internet Explorer version " + version + " is installed on the remote host.");
