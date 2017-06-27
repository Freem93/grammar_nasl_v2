#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17160);
  script_version("$Revision: 1.15 $");
  script_cve_id("CVE-2005-0478", "CVE-2005-0479", "CVE-2005-0480", "CVE-2005-0481", "CVE-2005-0482");
  script_bugtraq_id(12592);
  script_osvdb_id(13952, 13953, 13955, 13956, 13957, 13958);
 
  script_name(english:"TrackerCam Multiple Remote Vulnerabilities");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is affected by multiple vulnerabilities."
  );
  script_set_attribute(  attribute:"description",   value:
"The remote host is running TrackerCam, a HTTP software that allows a
user to publish a webcam feed thru a website.

The remote version of this software is affected by multiple
vulnerabilities :

  - Buffer overflows which may allow an attacker to execute
    arbitrary code on the remote host.

  - A directory traversal bug that may allow an attacker to
    read arbitrary files on the remote host with the 
    privileges of the web server daemon.

  - A cross-site scripting issue that may allow an attacker
    to use the remote host to perform a cross-site scripting
    attack."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/390918/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'TrackerCam PHP Argument Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/18");

 script_cvs_date("$Date: 2015/02/13 21:07:14 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_summary(english:"Checks for flaws in TrackerCam");
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 8090);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8090);

banner = get_http_banner(port:port);
if ( "Server: TrackerCam/" >!< banner ) exit(0);

w = http_send_recv3(method:"GET", item:"/tuner/ComGetLogFile.php3?fn=../HTTPRoot/tuner/ComGetLogFile.php3", port:port);
if (isnull(w)) exit(1, "the web server did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);
if ( "$fcontents = file ('../../log/'.$fn);" >< res )
{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

