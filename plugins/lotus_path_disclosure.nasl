#
# (C) Tenable Network Security, Inc.
#

# based on php3_path_disclosure by Matt Moore
#
# References
# From: "Peter_Grundl" <pgrundl@kpmg.dk>
# To: "bugtraq" <bugtraq@securityfocus.com>
# Subject: KPMG-2002006: Lotus Domino Physical Path Revealed
# Date: Tue, 2 Apr 2002 16:18:06 +0200
#

include("compat.inc");

if (description)
{
 script_id(11009);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");

 script_cve_id("CVE-2002-0245", "CVE-2002-0408");
 script_bugtraq_id(4049);
 script_osvdb_id(828, 15453);

 script_name(english:"IBM Lotus Domino Banner Nonexistent .pl File Request Path Disclosure");
 script_summary(english:"Tests for Lotus Physical Path Disclosure Vulnerability");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be a version of Lotus Domino that
allows an attacker to determine the physical path to the web root by
requesting a non-existent '.pl' file.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Feb/103");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Apr/14");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Apr/41");
 script_set_attribute(attribute:"solution", value:"Upgrade to Domino 5.0.10 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/07");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/08");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:lotus:domino");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

 script_family(english:"Web Servers");

 script_dependencie("iis_detailed_error.nasl", "404_path_disclosure.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Actual check starts here...

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/iis_detailed_errors"))  exit(0, "The web server listening on port "+port+" appears to be an instance of IIS that returns detailed error messages.");
if (get_kb_item("www/"+port+"/generic_path_disclosure"))  exit(0, "The web server listening on port "+port+" is known to be affected by a generic path disclosure vulnerability.");

url = "/cgi-bin/com5.pl";

res = test_generic_path_disclosure(item: url, 
                                   method: "GET", 
                                   port: port, 
                                   path_type: "windows",
                                   filename: "com5.pl", 
                                   exit_on_fail: TRUE);
 
if (!res) exit(0, "The web server listening on port "+port+" is not affected.");
