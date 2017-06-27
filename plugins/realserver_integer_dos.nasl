#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(15438);
  script_bugtraq_id(11352);
 script_version ("$Revision: 1.10 $");
  script_name(english:"Helix Universal Server Remote Integer Handling DoS");
 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Helix Universal Server, a digital media 
delivery platform.

There is a flaw in the remote version of this software that could allow 
an attacker to crash this service by sending a malformed POST request to
the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the most recent version of RealServer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/08");
 script_cvs_date("$Date: 2012/10/16 22:00:49 $");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:realnetworks:helix_universal_server");
 script_end_attributes();

  script_summary(english:"Checks the version of the remote HelixServer");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");
  script_copyright(english:"This script is (C) 2004-2012 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/http", 8080);   #port 7070, which may be indicative of server on 8080
  exit(0);
}



#
# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080, embedded: 1);

banner = get_http_banner(port:port, exit_on_fail: 1);
if ( egrep(pattern:"^Server: Helix Server Version ([0-8]\.[0-9]\..*|9\.0\.([0-3]|4\.([0-8]|9([0-4]|5[0-8])))|10\.([0-2]|3\.(0\.|1\.([0-6]|7(0|1[0-6])))))", string:banner) ) security_warning(port);
