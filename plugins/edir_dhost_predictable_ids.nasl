#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45109);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/14 15:38:18 $");

  script_cve_id("CVE-2009-4655");
  script_bugtraq_id(38782);
  script_osvdb_id(60035);
  script_xref(name:"Secunia", value:"38808");

  script_name(english:"Novell eDirectory DHost Predictable Session ID");
  script_summary(english:"Tries to determine if the session ID is predictable");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server generates predictable session IDs."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The eDirectory DHost web server running on the remote host generates
predictable session IDs.

A remote attacker could exploit this by predicting the session ID of
a legitimately logged-in user, which could lead to the hijacking of
administrative sessions."
  );
  script_set_attribute(
    attribute:"solution",
    value:"There is no known solution at this time."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_cwe_id(310);
  script_set_attribute(attribute:"vuln_publication_date",value:"2009/11/13");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/19");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:edirectory");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("http.inc");


port = get_http_port(default:8030, embedded:TRUE);

# Make sure this server looks like dhost
if (report_verbosity < 2)
{
  banner = get_http_banner(port:port);

  if (isnull(banner))
    exit(1, 'Unable to get web server banner on port '+port+'.');
  if (!egrep(string:banner, pattern:'Server: DHost'))
    exit(0, 'The web server on port '+port+' does not appear to be DHost.');
}

num_reqs = 5;
url = '/dhost';
last_id = NULL;
ids = make_list();
deltas = make_list();
min_delta = NULL;

# Get a bunch of session IDs.
for (i = 0; i < num_reqs; i++)
{
  clear_cookiejar();
  res = http_send_recv3(
    method:"GET",
    item:url,
    port:port,
    exit_on_fail:TRUE
  );
  str_id = get_any_http_cookie(name:'DHAC1');
  if (isnull(str_id)) exit(1, "A session ID wasn't received on port "+port+".");

  ids = make_list(ids, str_id);
  id = getdword(blob:hex2raw(s:str_id), pos:0);

  # only start calculating deltas after the 2nd response
  if (!isnull(last_id)) deltas = make_list(deltas, id - last_id);

  last_id = id;
}

# Determine if the deltas are predictable. We can account for gaps (i.e. other
# people attempting to login during the scan) assuming we're able to get at
# least two consecutive IDs.
min_delta = NULL;

foreach delta (deltas)
{
  if (isnull(min_delta) || delta < min_delta)
    min_delta = delta;
}

foreach delta (deltas)
{
  if (delta % min_delta != 0)
    exit(0, 'The web server on port '+port+' is not affected.');
}

# If we made it this far without bailing out, the system is vulnerable.
if (report_verbosity > 0)
{
  report =
    '\nNessus made '+num_reqs+' requests for the following URL :\n\n'+
    '  '+build_url(qs:url, port:port)+'\n\n'+
    'and received the following session IDs :\n\n';

  foreach id (ids) report += '  '+id+'\n';

  hex_delta = '0x'+hexstr(dec2hex(num:min_delta));
  report += '\nDelta : '+hex_delta+'\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
