#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25343);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2007-2975");
  script_bugtraq_id(24205);
  script_osvdb_id(36713);

  script_name(english:"Openfire Admin Console Remote Privilege Escalation");
  script_summary(english:"Tries to access Openfire's admin console");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server allows unauthenticated access to its
administrative console." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Openfire / Wildfire, an instant messaging
server supporting the XMPP protocol. 

The version of Openfire or Wildfire installed on the remote host
allows unauthenticated access to a servlet, which could allow a
malicious user to upload code to Openfire via its admin console." );
 script_set_attribute(attribute:"see_also", value:"http://www.igniterealtime.org/issues/browse/JM-1049" );
 script_set_attribute(attribute:"solution", value:
"Either firewall access to the admin console on this port or upgrade to
Openfire version 3.3.1 or later" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/02");
 script_cvs_date("$Date: 2016/05/12 14:46:29 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:igniterealtime:openfire");
 script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:9090);

# Try to access admin console.
w = http_send_recv3(method:"GET", item:"/dwr/index.html", port:port);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
res = w[2];

if (">downloader</a> (org.jivesoftware.openfire.update.PluginDownloadManager)<" >< res)
  security_hole(port);
