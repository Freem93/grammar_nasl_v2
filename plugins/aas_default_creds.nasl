#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38761);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/09/24 20:59:26 $");

  script_cve_id("CVE-2009-1465");
  script_bugtraq_id(34911);
  script_osvdb_id(54523);

  script_name(english:"A-A-S Application Access Server Default Admin Password");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is protected using default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote installation of A-A-S Application Access Server is
configured to use default credentials to control administrative access.
Knowing these, an attacker can gain administrative control of the
affected application and host.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/503434/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Change the password for the 'admin' user.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(255);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("aas_detect.nasl");
  script_require_ports("Services/www", 6262);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:6262, embedded: 0);
get_kb_item_or_exit("www/"+port+"/aas");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


user = "admin";
pass = "wildbat";


# Test the install.
init_cookiejar();

url = "/index.aas";
res = http_send_recv3(
  port     : port,
  method   : "GET",
  item     : url,
  username : user,
  password : pass
);
if (
  !isnull(res) &&
  "<TITLE>Application Access Server</TITLE>" >< res[2] &&
  (
    "HREF=index.aas?job=showprocess" >< res[2] ||
    "HREF=index.aas?job=eventlog" >< res[2]
  )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the following credentials :\n' +
      '\n' +
      '  URL      : ' + build_url(port:port, qs:url) + '\n' +
      '  User     : ' + user + '\n' +
      '  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
