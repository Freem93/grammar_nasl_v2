#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54604);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_bugtraq_id(47896);
  script_osvdb_id(72404);

  script_name(english:"MDaemon WorldClient < 12.0.3 Summary Page Email Subject XSS");
  script_summary(english:"Checks version of MDaemon");
 
  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote webmail client has a cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of MDaemon's WorldClient webmail
client running on this port is earlier than 12.0.3.  The LookOut theme
in such versions reportedly may interpret JavaScript in a message
subject in the Summary view. 

By sending a specially crafted email to a user who reads mail through
the affected webmail client, a remote attacker may be able to exploit
this issue to inject arbitrary HTML script code into the user's 
browser to be executed in the security context of the affected 
application."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://files.altn.com/MDaemon/Release/relnotes_en.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to MDaemon 12.0.3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:3000);
    
res = http_get_cache(item:"/", port:port, exit_on_fail:TRUE); 
if (
  'form action="/WorldClient.dll' >!< res &&
  "MDaemon" >!< res &&
  "/WorldClient" >!< res
) exit(0, "The web server listening on port "+port+" does not appear to be WorldClient.");


# Extract the version number from the login page.
version = strstr(res, "/WorldClient v");
version = version - strstr(version, " &copy; ");
version = strstr(version, " v") - " v";

if (!version || version !~ "^[0-9]+[0-9.]+$")
  exit(1, "Failed to extract the version from the WorldClient install on port "+port+".");

fixed_version = "12.0.3";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = 
      '\n  URL                : ' + build_url(port:port, qs:"/") +
      '\n  Installed version  : ' + version + 
      '\n  Fixed version      : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "WorldClient "+version+" is listening on port "+port+" and thus is not affected.");
