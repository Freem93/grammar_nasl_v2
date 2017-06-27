#
# Script by Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#
# Changes by Tenable:
# - Revised plugin title (12/30/2008)


include("compat.inc");

if(description)
{
 script_id(19602);
 script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2011/03/15 18:34:11 $");
 
 script_name(english:"LDU Software/Version Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a content management system written in
PHP." );
 script_set_attribute(attribute:"description", value:
"This script detects whether the remote host is running Land Down Under
(LDU) and extracts the version number and location if found. 

Land Down Under is a highly customizable and fully scalable content 
management system using PHP and MySQL.");
 script_set_attribute(attribute:"see_also", value:"http://www.neocrome.net/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/09");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "LDU detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"Copyright (C) 2005-2011 Josh Zlatin-Amishav");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);


foreach dir ( cgi_dirs() )
{
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it looks like LDU.
  if 
  (
    # Cookie from LDU
    "^Set-Cookie: LDUC" >< res ||
    # Meta tag (generator) from LDU
    'content="Land Down Under Copyright Neocrome' >< res || 
    # Meta tag (keywords) from LDU
    'content="LDU,land,down,under' >< res
  )
  {
    # First we'll try to grab the version from the main page
    pat = "Powered by <a [^<]+ LDU ([0-9.]+)<";
    matches = egrep(pattern:pat, string:res);
    if (matches)
    {
      foreach match (split(matches)) 
      {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) 
        {
          ver = ver[1];
          break;
        }
      }
    }

    #If unsuccessful try grabbing the version from the readme.old_documentation.htm file.
    if (isnull(ver)) 
    {
      req = http_get ( item:string (dir, "/docs/readme.old_documentation.htm"), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);
      pat = 'id="top"></a>Land Down Under v([0-9]+)<';
      matches = egrep(pattern:pat, string:res);
      if (matches)
      {
        foreach match (split(matches)) 
        {
          match = chomp(match);
          ver = eregmatch(pattern:pat, string:match);
          if (!isnull(ver)) 
          {
            ver = ver[1];
            break;
          }
        }
      }
    }

    if (isnull(ver)) ver = "unknown";

    # Generate report and update KB.
    #
    # nb: even if we don't know the version number, it's still useful
    #     to know that it's installed and where.
    if (dir == "") dir = "/";
    if (ver == "unknown")
    { 
      report = string(
        "An unknown version of Land Down Under is installed under ", dir, "\n",
        "on the remote host.");
    }
    else
    {
      report = string(
        "Land Down Under version ", ver, " is installed under ", dir, " on the\n",
        "remote host."
      );
    }
    security_note(port:port, extra:report);
    set_kb_item
    (
      name:string("www/", port, "/ldu"),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name:"www/ldu", value: TRUE);
  }
}
