#
# (C) Tenable Network Security, Inc.
#
 
include("compat.inc");

if (description)
{
  script_id(54615);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2011/05/23 18:27:02 $");

  script_name(english:"Device Type");
  script_summary(english:"Determines the remote device type");

  script_set_attribute(attribute:"synopsis", value:"It is possible to guess the remote device type.");
  script_set_attribute(attribute:"description", value:
"Based on the remote operating system, it is possible to determine
what the remote system type is (eg: a printer, router, general-purpose
computer, etc).");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/23");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
  script_family(english:"General");
  script_dependencies("os_fingerprint.nasl");
  script_require_keys("Host/OS/Type");
 
  exit(0);
}

#

type = get_kb_item("Host/OS/Type");
if ( isnull(type) ) exit(0, "Could not identify the remote device type.");
confidence = get_kb_item("Host/OS/Confidence");

report = 'Remote device type : ' + type  +'\n';
if ( !isnull(confidence) )
 report += strcat('Confidence level : ', confidence, '\n');

security_note(port:0, extra:report);
