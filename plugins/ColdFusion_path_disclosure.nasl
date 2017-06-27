#
# (C) Tenable Network Security, Inc.
#

#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# Modified by Paul Johnston for Westpoint Ltd to display the web root
#

include("compat.inc");

if(description)
{
 script_id(11393);
 script_version ("$Revision: 1.25 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-2002-0576");
 script_bugtraq_id(4542);
 script_osvdb_id(3337);

 script_name(english:"ColdFusion on IIS cfm/dbm Diagnostic Error Path Disclosure");
 script_summary(english:"Checks for a ColdFusion vulnerability");

 script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by a path
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote web server disclose the physical
path to its web root by requesting a MS-DOS device ending in .dbm (as
in nul.dbm)." );
 # https://web.archive.org/web/20041206154712/http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0028.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3991a459" );
 script_set_attribute(attribute:"solution", value:
"The vendor suggests turning on 'Check that file exists' :

   Windows 2000:
   1. Open the Management console
   2. Click on 'Internet Information Services'
   3. Right-click on the website and select 'Properties'
   4. Select 'Home Directory'
   5. Click on 'Configuration'
   6. Select '.cfm'
   7. Click on 'Edit'
   8. Make sure 'Check that file exists' is checked
   9. Do the same for '.dbm'" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/15");

 script_set_attribute(attribute:"cpe",value:"cpe:/a:allaire:coldfusion_server");
 script_set_attribute(attribute:"plugin_type", value:"remote");

 script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("iis_detailed_error.nasl", "404_path_disclosure.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/iis_detailed_errors"))  exit(0, "The web server listening on port "+port+" appears to be an instance of IIS that returns detailed error messages.");
if (get_kb_item("www/"+port+"/generic_path_disclosure"))  exit(0, "The web server listening on port "+port+" is known to be affected by a generic path disclosure vulnerability.");

url = "/nul.dbm";

res = test_generic_path_disclosure(item: url, 
                                   method: "GET", 
                                   port: port, 
                                   path_type: "windows",
                                   filename: "nul.dbm", 
                                   exit_on_fail: TRUE);
 
if (!res) exit(0, "The web server listening on port "+port+" is not affected.");
