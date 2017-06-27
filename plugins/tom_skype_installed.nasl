#
# (C) Tenable Network Security, Inc.
#

if( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if(description)
{
 script_id(34361);
 script_version ("$Revision: 1.6 $");
 script_cvs_date("$Date: 2011/03/21 15:22:44 $");
 
 script_name(english: "TOM-Skype Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"TOM-Skype is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"TOM-Skype is a variant of the popular 'Skype' VoIP application done in
conjunction with TOM Online, a popular Chinese Internet Provider. 

The remote version of TOM-Skype filters out some incoming keywords
that the official version of Skype does not, and apparently does not
guarantee the confidentiality of text messages sent through this
network." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c6babaf" );
 script_set_attribute(attribute:"see_also", value:"http://2006.recon.cx/en/f/vskype-part2.pdf");
 script_set_attribute(attribute:"see_also", value:"http://skype.tom.com" );
 script_set_attribute(attribute:"solution", value:
"Make sure that use of this software is in agreement with your
organization's security policies." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/07");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks version of Skype");
 
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
 script_family(english: "Windows");
 script_dependencie("skype_version.nbin");
 script_require_keys("Services/skype");
 exit(0);
}


port = get_kb_item("Services/skype");
if ( ! port ) exit(0);

vers = get_kb_item("Skype/" + port + "/skypeVersion");
if ( ! vers ) exit(0);
if ( vers =~ "^TOM-Skype" ) security_note(port);

