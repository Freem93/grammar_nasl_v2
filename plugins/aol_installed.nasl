# This script was written by Jeff Adams <jeffrey.adams@hqda.army.mil>
#

# Changes made by Tenable
#   - Updated description
#   - Added Synopsis/Solution/See also
#   - Revise title (10/9/09)
#   - Title touch-up (10/28/09)
#   - Added CPE (08/13/12)


include("compat.inc");

if(description)
{
 script_id(11882);
 
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2012/08/13 22:02:59 $");

 script_name(english:"AOL Instant Messenger (AIM) Software Detection (credentialed check)");
 script_summary(english:"Determines if AOL Instant Messenger is installed");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an instant messaging client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AOL Instant Messenger (AIM). AIM is a
commonly used chat client." );
 script_set_attribute(attribute:"see_also", value:"http://www.aim.com" );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this software agress with your organization's
security and acceptable use policies." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/15");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:aol:instant_messenger");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2012 Jeff Adams");
 
 script_family(english:"Windows");
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/AOL Instant Messenger/DisplayName";

if (get_kb_item (key))
  security_note(get_kb_item("SMB/transport"));
