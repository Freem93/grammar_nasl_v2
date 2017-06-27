#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20749);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-0339");
  script_bugtraq_id(16311);
  script_xref(name:"OSVDB", value:"22625");

  script_name(english:"BitComet Client .torrent URI Handling Overflow");
  script_summary(english:"Checks for URI buffer overflow vulnerability in BitComet"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a peer-to-peer application that is
affected by a remote buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of BitComet installed on the remote Windows host has a
buffer overflow flaw that could be triggered using a .torrent with a
specially crafted publisher's name to crash the application or even
execute arbitrary code remotely subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19a06781" );
 script_set_attribute(attribute:"see_also", value:"http://www.bitcomet.com/doc/changelog.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BitComet 0.61 or later, or remove the application." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/18");
 script_cvs_date("$Date: 2011/09/30 22:56:50 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("bitcomet_installed.nasl");
  script_require_keys("SMB/BitComet/Version");

  exit(0);
}


# Check version of BitComet.
ver = get_kb_item("SMB/BitComet/Version");
if (ver) {
  iver = split(ver, sep:'.', keep:FALSE);
  if (int(iver[0]) == 0 && int(iver[1]) < 61) security_hole(get_kb_item("SMB/transport"));
}
