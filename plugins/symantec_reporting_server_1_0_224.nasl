#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25458);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-3021", "CVE-2007-3022", "CVE-2007-3095");
  script_bugtraq_id(24312, 24313, 24325);
  script_osvdb_id(36107, 36108, 36109);

  script_name(english:"Symantec Reporting Server < 1.0.224.0 Multiple Vulnerabilities");
  script_summary(english:"Tries to bypass authentication in Reporting Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Symantec Reporting Server, a web-based tool
for creating reports about Symantec enterprise antivirus products. 

The version of Symantec Reporting Server installed on the remote host
allows a remote attacker to bypass authentication to various scripts
and gain access to the application. 

Additionally, it reportedly allows a user to create a malicious
executable in the process of exporting data. This could, in turn, be
executed in the context of the web server user, and may display the
administrator's hashed password after failed login attempts, which
might allow an attacker to gain control of the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2007.06.05.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2007.06.05a.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Reporting Server version 1.0.224.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/05");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/06/05");
 script_cvs_date("$Date: 2013/04/03 22:02:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:client_security");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:norton_antivirus");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:reporting_server");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Check whether we get beyond the authentication check.
w = http_send_recv3(method:"GET", item:"/Reporting/login/change_password.php?enable_auth=0", port:port);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
res = w[2];

# There's a problem if...
if (
  # we gain access to the Change Password page and...
  "title>Reporting - Change Password<" >< res &&
  # we're logged on.
  "Logged on as: <b>logged out</b>" >< res
)  security_hole(port);
