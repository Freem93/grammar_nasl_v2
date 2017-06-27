#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18059);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id("CVE-2005-1122", "CVE-2005-1123");
  script_bugtraq_id(13187, 13188);
  script_osvdb_id(15511, 15512);
  script_xref(name:"GLSA", value:"200504-14");

  script_name(english:"Monkey HTTP Daemon (monkeyd) < 0.9.1 Multiple Vulnerabilities");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Monkey HTTP Server installed on the remote host
suffers from the following flaws :

  - A Format String Vulnerability
    A remote attacker may be able to execute arbitrary code with the
    permissions of the user running monkeyd by sending a specially-
    crafted request.

  - A Denial of Service Vulnerability
    Repeatedly requesting a zero-byte length file, if one exists, 
    could cause the web server to crash.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.gentoo.org/show_bug.cgi?id=87916");
  script_set_attribute(attribute:"solution", value:"Upgrade to monkeyd 0.9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:monkey-project:monkey_http_daemon");
  script_end_attributes();

  script_summary(english:"Checks for multiple vulnerabilities in Monkey HTTP Daemon < 0.9.1");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 2001);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:2001);

# Make sure it's Monkey.
banner = get_http_banner(port:port);
if (!banner) exit(1, "No web banner on port "+port);
if (!egrep(pattern:"^Server:.*Monkey/", string:banner)) exit(0, "Monkey web server is not running on port "+port);


# If safe chceks are enabled, check the version number.
if (safe_checks()) {
  if (egrep(string:banner, pattern:"^Server: +Monkey/0\.([0-8]|9\.[01][^0-9])")) {
    report = string(
      "\n",
      "Nessus has determined the vulnerability exists on the remote host\n",
      "simply by looking at the version number of Monkey HTTP Daemon\n",
      "installed there.\n"
    );
    security_hole(port:port, extra:report);
  }
}
# Otherwise, try to crash it.
#
# nb: this *should* just crash the child processing the request, 
#     not the parent itself.
else if (report_paranoia == 2) {

  # Make sure it's up first.
  if (http_is_dead(port:port)) exit(1, "Web server on port "+port+" is dead");

  # And now, exploit it.
  soc = http_open_socket(port);
  w = http_send_recv_buf(port: port, data: 'GET %%00 HTTP/1.1\nHost: %%500n%%500n\n\n');
  if (isnull(w)) security_hole(port);
}
