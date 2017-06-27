#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25548);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2007-3273");
  script_bugtraq_id(24498);
  script_osvdb_id(38470);

  script_name(english:"FuseTalk index.cfm txForumID Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a ColdFusion script that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running FuseTalk, a discussion forum implemented in
ColdFusion. 

The version of FuseTalk installed on the remote host fails to properly
sanitize user-supplied input to the 'txForumID' parameter before using
it in the 'forum/include/error/forumerror.cfm' script in database
queries.  An unauthenticated, remote attacker can leverage this issue
to launch SQL injection attacks against the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jun/226" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/16");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:fusetalk:fusetalk");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);


exploit = string("'", SCRIPT_NAME);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/fusetalk/forum", "/forums/forum", "/forum/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the affected script exists.
  url = string(dir, "/include/error/forumerror.cfm");

  w = http_send_recv3(method:"GET", item:string(url, "?errorno=3"), port:port);
  if (isnull(w)) exit(1, "The web server did not answer");
  res = strcat(w[0], w[1], '\r\n', w[2]);

  # If it does...
  if (
    'name="FT_ACTION" ' >< res &&
    res =~ 'NAME="txForumID" '
  )
  {
    postdata = string(
      "txForumID=", urlencode(str:exploit), "&",
      "FT_ACTION=SearchURL"
    );
    w = http_send_recv3(method:"POST", item: url, port: port,
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(w)) exit(1, "the web server did not answer");
    res = strcat(w[0], w[1], '\r\n', w[2]);

    # There's a problem if we see a SQL error.
    if (
      "<title>Error Occurred While Processing Request" >< res &&
      (
        string("near ", exploit, " and vchsettingname =") >< res ||
        string("where iforumid = ", exploit, " and vchsettingname =") >< res
      )
    )
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
