#
# Josh Zlatin-Amishav GPLv2
#
# 


include("compat.inc");

if (description) {
  script_id(19585);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/03/16 14:54:11 $");

  name["english"] = "Mercora IMRadio Detection";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a Internet radio application installed." );
 script_set_attribute(attribute:"description", value:
"Mercora IMRadio is installed on the remote host.  Mercora is an 
Internet radio tuner that also provides music sharing, instant 
messaging, chat, and forum capabilities.  This software may not be
suitable for use in a business environment." );
 script_set_attribute(attribute:"see_also", value:"http://www.mercora.com/default2.asp" );
 script_set_attribute(attribute:"solution", value:
"N/A" );
 script_set_attribute(attribute:"risk_factor", value:
"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/06");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  summary["english"] = "Checks for Mercora IMRadio";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Josh Zlatin-Amishav");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);


# Look in the registry for evidence of Mercora.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Mercora/DisplayName";
if (get_kb_item(key)) security_note(get_kb_item("SMB/transport"));
