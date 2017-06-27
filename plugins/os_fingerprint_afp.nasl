#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53331);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/06/12 11:01:43 $");

  script_name(english:"OS Identification : Apple Filing Protocol");
  script_summary(english:"Determines the remote operating system");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on the
capabilities of the remote AFP server.");
  script_set_attribute(attribute:"description", value:
"This script attempts to identify the operating system type and version
by looking at the capabilities of the remote Apple Filing Protocol
Server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
  script_family(english:"General");

  script_dependencies("asip-status.nasl");
  script_require_keys("Host/OS/AFP/fingerprint");
  exit(0);
}


caps = get_kb_item("Host/OS/AFP/fingerprint");
if ( ! caps ) exit(0, "No fingerprints");

confidence = 69;
name = NULL;

if ( caps == "AFP3.4, AFP3.3, AFP3.2, AFP3.1, AFPX03") { name = 'Mac OS X 10.6\nMac OS X 10.7\nMac OS X 10.8\nMac OS X 10.9\nMac OS X 10.10'; confidence -= 6; }
if ( caps == "AFP3.3, AFP3.2, AFP3.1, AFPX03, AFP2.2") { name = 'Mac OS X 10.5\nMac OS X 10.6'; confidence -= 4; }
if ( caps == "AFP3.2, AFP3.1, AFPX03, AFP2.2" ) name = "Mac OS X 10.4";
if ( caps == "AFP3.1, AFPX03, AFP2.2" ) { name = 'Mac OS X 10.3\nMac OS X 10.2'; confidence -= 4; }
# Netatalk: AFPVersion 1.1, AFPVersion 2.0, AFPVersion 2.1, AFP2.2, AFPX03, AFP3.1, AFP3.2

if ( !isnull(name) )
{
 set_kb_item(name:"Host/OS/AFP", value:name);
 set_kb_item(name:"Host/OS/AFP/Confidence", value:confidence);
 set_kb_item(name:"Host/OS/AFP/Type", value:"general-purpose");
}
