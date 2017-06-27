#
# (C) Tenable Network Security, Inc.
#
# Ref:
#  From: "Berend-Jan Wever" <SkyLined@edup.tudelft.nl>
#  To: <bugtraq@securityfocus.com>, <full-disclosure@lists.netsys.com>,
#        "Windows NTBugtraq Mailing List" <NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM>,
#        "vulnwatch" <vulnwatch@vulnwatch.org>
#  Date: Mon, 7 Apr 2003 18:47:57 +0200
#  Subject: [VulnWatch] Coppermine Photo Gallery remote compromise


include("compat.inc");


if(description)
{
 script_id(11524);
 script_bugtraq_id(7300);
 script_osvdb_id(50624);
 script_version ("$Revision: 1.18 $");

 script_name(english:"Coppermine Photo Gallery Multiple Extension File Upload Arbitrary PHP Code Execution");
 script_summary(english:"Checks for the presence of db_input.php");

 script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server has a remote code
execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Coppermine Gallery - a set of PHP scripts
designed to handle galleries of pictures.

This product has a vulnerability which allows an attacker to upload
a rogue jpeg file which may contain PHP commands.  A remote attacker
could use this to execute arbitrary commands in the context of the
web server." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/vulnwatch/2003/q2/13"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Coppermine 1.1 beta 2 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/07");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("coppermine_gallery_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

kb = get_kb_list("www/" + port + "/coppermine_photo_gallery");
if ( isnull(kb) ) exit(0);

foreach k ( kb )
{
 version = split(k, sep:" under ", keep:0);
 if ( ereg(pattern:"^v?(0\.|1\.(0\.|1 (devel|Beta 1)))", string:version[0], icase:TRUE) )
 	{
	security_hole(port);
	exit(0);
	}
}

