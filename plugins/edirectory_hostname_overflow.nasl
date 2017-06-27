#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22903);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/15 13:39:09 $");

  script_cve_id("CVE-2006-5478");
  script_bugtraq_id(20655);
  script_osvdb_id(29993);
  script_xref(name:"Secunia", value:"22519");

  script_name(english:"Novell eDirectory iMonitor HTTP Protocol Stack (httpstk) Host HTTP Header Remote Overflow");
  script_summary(english:"Send a special Host request header to eDirectory");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is affected by a buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Novell eDirectory on the remote host
reportedly contains a buffer overflow that can be triggered with a
specially crafted Host request header.  An anonymous remote attacker
may be able to leverage this flaw to execute code on the affected
host, generally with super-user privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mnin.org/advisories/2006_novell_httpstk.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2006/Oct/433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/filefinder/security/index.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the eDirectory Post 8.7.3.8 FTF1 / 8.8.1 FTF1 patch as
appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell eDirectory NDS Server Host Header Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/23");
  script_set_attribute(attribute:"patch_publication_date", value: "2006/10/23");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/10/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:edirectory");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8028);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8028, embedded:TRUE);


# Make sure the server looks like eDirectory.
banner = get_http_banner (port:port);
if (!egrep(pattern:"Server: .*HttpStk/[0-9]+\.[0-9]+", string:banner))
  exit(0, "The web server on port "+port+" is not HttpStk.");


# Get the format of a normal host location

r = http_send_recv3(port:port, method:"GET", exit_on_fail: 1, item:"/nds",
  add_headers: make_array("Host", "nessus"), follow_redirect: 0);

res = egrep(pattern: "^Location: https?://nessus:[0-9]+/nds", string: r[1]);
if (res == NULL)
  exit (0, "Could not find redirection in response from port "+port+".");

# Create a special host location string

v = eregmatch(string: res, pattern:"^Location: (https?://)nessus:([0-9]+)/nds");
if (isnull(v)) exit(1, "Could not parse Location header from port "+port+".");
http = v[1]; sport = v[2];

magic = crap(data:"A", length:62 - strlen(http) - strlen(sport));
r = http_send_recv3(method:"GET", item:"/nds", port:port, exit_on_fail: 1,
  add_headers: make_array("Host", magic), follow_redirect: 0);

res = egrep(pattern:"^Location:", string:r[1]);
if (res == NULL)
  exit (1, "Could not find Location line from port "+port+".");
v = eregmatch(string: res, pattern:"^Location: *(https?://A+:[0-9]+/nds)");
if (isnull(v)) exit(1, "Could not parse Location header from port "+port+".");
s = v[1];
# Patched version should skip 1 character in the port number
if (strlen(s) == 67)
  security_hole(port);
