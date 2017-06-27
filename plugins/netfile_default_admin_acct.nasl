#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18294);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_name(english:"NETFile Default Credentials");
  script_summary(english:"Checks for default admin user / password vulnerability in NETFile FTP/Web Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP / web server uses a default set of administrative
credentials.");
  script_set_attribute(attribute:"description", value:
"The version of NETFile FTP/Web server installed on the remote host uses
the default admin user and password, root/root.  An attacker can exploit
this issue to alter the affected application's configuration.");
  script_set_attribute(attribute:"solution", value:"Change the admin user's password with the NETFile GUI.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:fastream:netfile_ftp_web_server");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Try to log in as root/root through the remote admin server.

postdata = '<?xml version="1.0"?>\r\n' +
  '<message><type>request</type><adminlogindata><username>Root</username><password>root</password></adminlogindata><requestType>INITIALIZE</requestType><data/></message>\r\n';
w = http_send_recv3(method:"POST", item:"/", port: port,
  content_type: "application/x-www-form-urlencoded",
  add_headers: make_array("Accept", "text/html, */*",
  	       "User-Agent", "Fastream NETFile Server",
	       "Cache-Control", "no-cache"),
  data: postdata,
  exit_on_fail:TRUE);

res = w[2];
if ("<message><type>response</type><responseType>INITIALIZE</responseType>" >< res) security_hole(port);
else audit(AUDIT_HOST_NOT, "affected");
