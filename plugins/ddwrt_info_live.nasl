#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
  script_id(51394);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/15 13:39:09 $");

  script_bugtraq_id(45598);
  script_osvdb_id(70230);

  script_name(english:"DD-WRT Info.live.htm Information Disclosure");
  script_summary(english:"Requests /Info.live.htm");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of DD-WRT installed on the remote device allows an
unauthenticated, remote attacker to retrieve sensitive information
about the router itself and any attached hosts, such as geolocation
information, IP addresses, MAC addresses and host names, even if
remote administration is disabled."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Dec/651"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.dd-wrt.com/phpBB2/viewtopic.php?t=84931"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded:TRUE);


# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();


# Unless we're paranoid, make sure that the server looks like DD-WRT.
if (report_paranoia < 2)
{
  file = http_get_cache(port:port, item:"/", exit_on_fail:TRUE);
  if (
    "http://www.dd-wrt.com/" >!< file &&
    ">DD-WRT Control Panel<" >!< file
  ) exit(0, "The server listening on port "+port+" does not look like DD-WRT.");
}


# Check if the page is accessible.
url = '/Info.live.htm';
res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

if (
  '{lan_mac::' >< res[2] &&
  '{wan_mac::' >< res[2] &&
  '{dhcp_leases::' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to verify the issue using the following URL :\n' +
      '\n' +
      '  ' + build_url(port:port, qs:url) + '\n';

    if (report_verbosity > 1)
    {
      report += 
        '\n' +
        'Here are the contents of that page :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        res[2] +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else exit(0, "The web server listening on port "+port+" is not affected.");
