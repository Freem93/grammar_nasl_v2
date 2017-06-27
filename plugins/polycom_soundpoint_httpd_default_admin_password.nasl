#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55403);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/21 20:34:20 $");

  script_name(english:"Polycom SoundPoint IP Phone Default Password");
  script_summary(english:"Tries to access phone configuration with default credentials.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is using default web configuration credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Polycom SoundPoint IP phone is using default credentials
to protect some of its configuration pages.  A remote attacker could
use this information to mount further attacks."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Configure the device to use chosen credentials rather than the
default credentials."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded:TRUE);
banner = get_http_banner(port:port, exit_on_fail:TRUE);

if ("Server: Polycom SoundPoint" >!< banner)
  audit(AUDIT_WRONG_WEB_SERVER, port, "from a Polycom SoundPoint device");

if ( supplied_logins_only ) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Default creds are: Polycom / 456
default_auth_str = "Basic UG9seWNvbTo0NTY=";

urls_to_try = make_list('/netConf.htm', '/appConf.htm', '/req_1.htm');

foreach url_to_try (urls_to_try)
{
  res = http_send_recv3(
    method       : "GET", 
    item         : url_to_try,
    port         : port,
    exit_on_fail : TRUE
  );

  # If response is not 401, try another page
  if (res[0] !~ "^HTTP\/1\.[01] 401") continue;

  # If 401, try with default creds
   res = http_send_recv3(
    method       : "GET", 
    item         : url_to_try,
    port         : port, 
    add_headers  : make_array("Authorization", default_auth_str)
  ); 

  if (
    res[0] =~ "^HTTP\/1\.[01] 200 " &&
    res[2] =~ "<title>Polycom - Sound(Station|Point) IP Configuration Utility</title>"
  )
  {
    access_was_granted = TRUE;
    break;
  }
}

if (!isnull(access_was_granted))
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the following information :\n' +
      '\n  URL      : ' + build_url(port:port, qs:url_to_try) +
      '\n  User     : Polycom' +
      '\n  Password : 456' +
      '\n';
    security_hole(port:port, extra:report);
  } 
  else security_hole(port);
}
else audit(AUDIT_HOST_NOT, "affected");
