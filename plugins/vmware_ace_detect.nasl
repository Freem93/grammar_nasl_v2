#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31727);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2012/08/10 19:03:18 $");

  script_name(english:"VMware ACE detection (Windows)");
  script_summary(english:"Checks version of VMware ACE installed"); 
 
 script_set_attribute(attribute:"synopsis", value:
"An OS Virtualization management application is installed on the remote 
host." );
 script_set_attribute(attribute:"description", value:
"VMware ACE, an OS virtualization management solution, is installed 
on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/products/ace/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/02");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:a:vmware:ace");
 script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

port = kb_smb_transport();

# Figure out where the installer recorded information about it.

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

installstring = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && "VMware ACE Management Server" >< prod)
  {
   installstring = ereg_replace(pattern:"^(SMB\/Registry\/HKLM\/SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
   break;
  }
}

if(isnull(installstring)) exit(0);

ace_version = NULL;
ace_version = get_kb_item(string(installstring,"/","DisplayVersion"));

if(!isnull(ace_version))
{
 set_kb_item(name:"VMware/ACE/Version", value:ace_version);

 if(report_verbosity)
 {
  report = string(
          "VMware ACE version ", ace_version, " is installed on the remote host.",
          "\n"
    );
   security_note(port:port, extra:report);  
 }
 else
  security_note(port:port);
}

exit(0);
