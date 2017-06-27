#
# (C) Tenable Network Security, Inc.
#

# Note: Based on the proof of concept example,  NOT fully tested
#
# Reference: http://www.example.com/modules.php?op=modload&name=Downloads&file=index&req=addrating&ratinglid=[DOWNLOAD ID]&ratinguser=[REMOTE USER]&ratinghost_name=[REMOTE HOST ;-)]&rating=[YOUR RANDOM CONTENT] 
#


include("compat.inc");

if (description)
{
 script_id(11676);
 script_version("$Revision: 1.20 $"); 
 script_cvs_date("$Date: 2014/07/11 19:38:17 $");

 script_bugtraq_id(7702);
 script_osvdb_id(5500);

 script_name(english:"PostNuke Rating System DoS");
 script_summary(english:"Determine if the remote host is affected by the PostNuke rating DoS vulnerability");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PostNuke.  PostNuke Phoenix 0.721, 0.722
and 0.723 allows a remote attacker causes a denial of service to
legitmate users, by submitting a string to its rating system." );
 script_set_attribute(attribute:"solution", value:
"Add vendor-supplied patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:postnuke");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_dependencie("postnuke_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/postnuke");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
version = stuff[1];

if(ereg(pattern:"^0\.([0-6]\.|7\.([0-1]\.|2\.[0-3]))", string:version)) 
	security_warning(port);
