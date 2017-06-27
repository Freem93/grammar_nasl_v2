#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19386);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2011/03/16 14:54:11 $");

  script_name(english:"Ares Fileshare Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a peer-to-peer filesharing
application." );
 script_set_attribute(attribute:"description", value:
"Ares Fileshare is installed on the remote host.  Ares Fileshare is a
P2P application that supports connecting to several P2P networks; eg,
Gnutella and OpenFT.  As such, it may not be suitable for use in a
business environment. 

In addition, note that it's not possible for Nessus to determine the
installed version of Ares Fileshare and that some versions suffer from
remotely exploitable vulnerabilities; eg, Bugtraq 14377.

This product has been discontinued and is no longer supported." );
 script_set_attribute(attribute:"solution", value:
"Remove the program from the remote host." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/04");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();
 
  summary["english"] = "Detects Ares Fileshare";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for evidence of Ares Fileshare.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Ares Fileshare/DisplayName";
if (get_kb_item(key)) security_note(get_kb_item("SMB/transport"));
