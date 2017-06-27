#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11430);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_name(english:"WinMX Detection");
  script_summary(english:"Determines if WinMX is installed");

  script_set_attribute(
    attribute:'synopsis',
    value:'WinMX is a peer-to-peer file sharing application.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is using WinMX, a p2p file sharing application, which may not
be suitable for a business environment."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Uninstall this software."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.ca.com/us/securityadvisor/pest/pest.aspx?id=453073289'
  );


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/21");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"Peer-To-Peer File Sharing");
  script_dependencies("netbios_name_get.nasl", "smb_login.nasl","smb_registry_access.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport");
  script_require_ports(139, 445);
  exit(0);
}


if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/WinMX/DisplayName";

if (get_kb_item (key))
  security_warning(get_kb_item("SMB/transport"));
