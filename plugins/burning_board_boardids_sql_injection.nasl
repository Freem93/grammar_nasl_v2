#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24223);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-0388");
  script_bugtraq_id(22096);
  script_osvdb_id(33872);
  script_xref(name:"EDB-ID", value:"3143");
  script_xref(name:"EDB-ID", value:"3144");
  script_xref(name:"EDB-ID", value:"3146");

  script_name(english:"WoltLab Burning Board search.php Multiple Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of Burning Board / Burning Board Lite on the remote host
fails to sanitize user input to the 'boardids' parameter of the
'search.php' script before using it in database queries.  Regardless
of PHP's 'register_globals' and 'magic_quotes_gpc' settings, an
unauthenticated, remote attacker can leverage this issue to launch SQL
injection attacks against the affected application, including
discovery of password hashes of users of the application." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/18");
 script_cvs_date("$Date: 2011/08/31 17:29:19 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("burning_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

init_cookiejar();

# Test any installs.
wbb = get_kb_list(string("www/", port, "/burning_board"));
wbblite = get_kb_list(string("www/", port, "/burning_board_lite"));
if (isnull(wbb))
{
  if (isnull(wbblite)) exit(0);
  else installs = make_list(wbblite);
}
else if (isnull(wbblite))
{
  if (isnull(wbb)) exit(0);
  else installs = make_list(wbb);
}
else
{
  kb1 = get_kb_list(string("www/", port, "/burning_board"));
  kb2 = get_kb_list(string("www/", port, "/burning_board_lite"));
  if ( isnull(kb1) ) kb1 = make_list();
  else kb1 = make_list(kb1);
  if ( isnull(kb2) ) kb1 = make_list();
  else kb2 = make_list(kb2);
  installs = make_list(kb1, kb2);
}
foreach install (installs)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];

    # First we need some text to search for.
    idx = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

    pat = '<a href="thread\\.php\\?goto=lastpost.+ title="([^"]+)">';
    titles = make_list();
    matches = egrep(pattern:pat, string: idx);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        value = eregmatch(pattern:pat, string:match);
        if (!isnull(value))
        {
          titles = make_list(titles, value[1]);
        }
      }
    }

    # If we have some...
    word = NULL;
    if (max_index(titles))
    {
      # Make sure the affected script exists.
      url = string(dir, "/search.php");
      r = http_send_recv3(port: port, method: 'GET', item: url);
      if (isnull(r)) exit(0);

      # If it does...
      if ('<select name="boardids[]"' >< r[2])
      {
        # Try the PoC using words in the titles, if they're long enough.
        # 
        # nb: search term must be between 3 and 19 characters, at least in WBB Lite
        checked = 0;
        foreach title (titles)
        {
          while (!checked && strlen(title))
          {
            matches2 = eregmatch(pattern:"(^| )([a-zA-Z]{3,19})( |$)", string:title);
            if (isnull(matches2)) title = "";
            else
            {
              word = matches2[2];

              # Try to exploit the flaw to generate a SQL error.
              sql = string(rand() % 100, ") ", SCRIPT_NAME);
              postdata = string(
                "searchstring=", word, "&",
                "searchuser=&",
                "name_exactly=1&",
                "boardids[]=", urlencode(str:sql), "&",
                "showposts=0&",
                "searchdate=0&",
                "beforeafter=after&",
                "sortby=lastpost&",
                "sortorder=desc&",
                "send=send&",
                "submit=Suchen"
              );
	      set_http_cookie(name: "wbb_userpassword", value: "0");
              r = http_send_recv3(port:port, method: 'POST', item: url, 
version: 11, data: postdata, 
add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );
              if (isnull(r)) exit(0);

              # There's a problem if we see an error.
              if (
                "SQL-DATABASE ERROR" >< r[2] &&
                string("boards WHERE boardid IN (0,", sql, ")") >< r[2]
              )
              {
                security_hole(port);
		set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
                exit(0);
              }

              title = ereg_replace(pattern:string("^.*", word, "(.*)$"), replace:"\1", string:title);

              # We checked for the flaw as long as we didn't see "Your search 
              # is invalid", which means the word was on a banned list and 
              # the search didn't work.
              if ("Your search is invalid" >!< r[2]) checked = 1;
            }
          }
          if (checked) break;
        }
      }
    }

    if (!checked)
    {
      debug_print("couldn't find a search term to use!");
    }
  }
}
