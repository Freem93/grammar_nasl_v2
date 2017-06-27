#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18012);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2011/03/16 14:54:11 $");

  script_cve_id("CVE-2005-1089");
  script_bugtraq_id(13088);
  script_osvdb_id(15433);

  script_name(english:"DC++ Download Drive Arbitrary File Appending");
  script_summary(english:"Checks for download drive file appending vulnerability in DC++");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
file integrity flaw." );
  script_set_attribute(attribute:"description", value:
"According to its version number, the DC++ client installed on the
remote host is affected by a vulnerability that may let a remote user
append data to files anywhere on the drive on which DC++ is
installed." );
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?group_id=40287&release_id=319316" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to DC++ 0.674 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/12");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/11");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


# Look in the registry for the version of DC++ installed.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/DC++/DisplayVersion";
ver = get_kb_item(key);
if (ver && ver =~ "^0\.([0-5]|6([0-6]|7[0-3]))")
  security_warning(get_kb_item("SMB/transport"));
