#
# Written by:
# This script is Copyright (C) 2005 Tom Ferris
# GPLv2
# <tommy@security-protocols.com>
# 6/29/2005
# www.security-protocols.com
#

# Changes by Tenable:
# - Revised plugin title (11/25/09)

include("compat.inc");

if(description)
{
 script_id(18591);
 script_version("$Revision: 1.6 $");
 script_cvs_date("$Date: 2011/03/16 14:54:11 $");

 script_name(english:"Plaxo Client Detection");

 script_set_attribute(attribute:"synopsis", value:
"Plaxo Client is installed." );
 script_set_attribute(attribute:"description", value:
"The remote host has the Plaxo Client software installed.  Plaxo is a
contact manager." );
 script_set_attribute(attribute:"solution", value:
"Ensure that use of this software agrees with your organization's 
acceptable use and security policies." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/29");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_summary(english:"Determines if Plaxo is installed");

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tom Ferris <tommy@security-protocols.com>");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

#

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Plaxo/DisplayName";

if (get_kb_item (key))
  security_note(get_kb_item("SMB/transport"));
