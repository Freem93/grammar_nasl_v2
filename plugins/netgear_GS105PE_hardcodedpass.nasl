#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76475);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:17:13 $");

  script_cve_id("CVE-2014-2969");
  script_bugtraq_id(68366);
  script_osvdb_id(108713);
  script_xref(name:"CERT", value:"143740");

  script_name(english:"NETGEAR GS105PE Pro Safe Switch Hard-coded Credentials");
  script_summary(english:"Tries to log in using hard-coded credentials.");

  script_set_attribute(attribute:'synopsis', value:"The remote service has well known hard-coded credentials.");
  script_set_attribute(attribute:'description', value:
"The NETGEAR GS105PE Pro Safe Switch has a set of hard-coded
credentials ('ntguser / debugpassword') that give access to several
CGI control scripts and could allow a remote attacker to :

   - Modify the serial number and MAC address of the
    product. (produce_burn.cgi)

   - Manually set memory to a certain value and extract
    that value from it. (register_debug.cgi)

   - Upload new firmware. (bootcode_update.cgi)");
  script_set_attribute(attribute:'solution', value:"No known solution.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/11");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:netgear:gs105pe");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:gs105pe_firmware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www",80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, embedded:1);

banner = get_http_banner(port:port, exit_on_fail:TRUE);
if ('Basic realm="Switch"' >!< banner) audit(AUDIT_WRONG_WEB_SERVER, port, "a NETGEAR device");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user     = "ntguser";
pass     = "debugpassword";

str1 = "<title>Produce Burn-in</title>";
str2 = "<legend>Produce Burn-in</legend>";
targ     = "/produce_burn.cgi";

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

# Check for paranoid weirdness
if (report_paranoia < 2)
{
  response = http_send_recv3(
    method:"GET",
    item: targ,
    port: port,
    exit_on_fail: 1
  );
  if (str1 >< response[2] && str2 >< response[2]) exit(1, build_url(port:port, qs:targ)+" is accessible without authentication.");
}

# Check for login
response = http_send_recv3(
  method:"GET",
  item: targ,
  port: port,
  username: user,
  password: pass,
  exit_on_fail: 1
);

if (str1 >< response[2] && str2 >< response[2])
{
  if (report_verbosity > 0)
  {
    header  = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials : \n'+
      '\n  User name  : ' + user +
      '\n  Password   : ' + pass;
    report = get_vuln_report(
      items   : targ,
      port    : port,
      header  : header,
      trailer : trailer
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "NETGEAR web server", port);
