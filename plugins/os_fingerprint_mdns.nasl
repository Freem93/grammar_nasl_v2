#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25245);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/03/21 15:22:43 $");

  name["english"] = "OS Identification : mDNS";
  script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based
on the data returned by the mDNS server." );
 script_set_attribute(attribute:"description", value:
"This script attempts to identify the Operating System type and 
version by looking at the data returned by the mDNS server." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Determines the remote operating system";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencies("mdns.nasl");
  script_require_keys("mDNS/os");
  exit(0);
}


if ( (os = get_kb_item("mDNS/os")) )
{
	 #
 	 # Mac OS X reveals its full version number
	 # 
         set_kb_item(name:"Host/OS/mDNS/Fingerprint", value:os);
	 if ( "Mac OS X" >< os )
	 {
          set_kb_item(name:"Host/OS/mDNS", value:os);
          set_kb_item(name:"Host/OS/mDNS/Confidence", value:100);
	 }
	 else if ( "LINUX" >< os )
	 {
          set_kb_item(name:"Host/OS/mDNS", value:"Linux Kernel");
          set_kb_item(name:"Host/OS/mDNS/Confidence", value:30);
 	 }
	 else 
	 {
	  #
	  # What is this ?
          #
          set_kb_item(name:"Host/OS/mDNS", value:os);
          set_kb_item(name:"Host/OS/mDNS/Confidence", value:20);
	 }
}

