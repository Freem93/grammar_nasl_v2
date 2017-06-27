#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18016);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/01/24 17:54:57 $");

  name["english"] = "DC++ Detection";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a peer-to-peer filesharing
application." );
 script_set_attribute(attribute:"description", value:
"DC++ is installed on the remote host.  DC++ is an open source client
for the Direct Connect peer-to-peer file-sharing protocol and may not
be suitable for use in a business environment." );
 script_set_attribute(attribute:"see_also", value:"http://dcplusplus.sourceforge.net/" );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this program is in accordance with your corporate
security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/12");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value: "cpe:/a:linux:direct_connect");
script_end_attributes();

 
  summary["english"] = "Checks for DC++";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for evidence of DC++.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/DC++/DisplayName";
if (get_kb_item(key)) security_note(get_kb_item("SMB/transport"));
