#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35609);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2009-0400");
  script_bugtraq_id(33495);
  script_osvdb_id(51644);
  script_xref(name:"EDB-ID", value:"7900");

  script_name(english:"SocialEngine Blog Plugin category_id Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL injection error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SocialEngine, a PHP-based social network
platform. 

The version of the Blog plugin for SocialEngine installed on the
remote host fails to sanitize input to the 'category_id' parameter of
the 'blog.php' script before using it to construct database queries. 
Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
attacker may be able to exploit this issue to manipulate database
queries, leading to disclosure of sensitive information or attacks
against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.socialenginebase.net/viewtopic.php?f=15&t=474" );
 script_set_attribute(attribute:"solution", value:
"Either upgrade to the Blogs plugin version 3.05 or later or patch the
affected file as described in the forum posting referenced above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/06");
 script_cvs_date("$Date: 2016/05/19 18:02:19 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/socialengine", "/socialnetwork", "/community", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Get a list of available blogs.
  url = string(dir, "/browse_blogs.php");

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If it looks like Social Engine...
  if (
    'var SocialEngine = new SocialEngineAPI.Base' >< res[2] ||
    '>Browse Blog Entries<' >< res[2] || 
    "value='blogentry_" >< res[2]
  )
  {
    # Identify a user's blog.
    profile = NULL;

    pat = "blog\.php\?user=([^ $&]+)&blogentry_id=";
    matches = egrep(pattern:pat, string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          profile = item[1];
          break;
        }
      }
    }
    if (isnull(profile))
    {
      debug_print("couldn't find a user profile to use!", level:1);
      continue;
    }

    # Try to exploit the issue to generate a syntax error.
    exploit = string("-5 ", SCRIPT_NAME);
    url = string(
      dir, "/blog.php?",
      "user=", profile, "&",
      "category_id=", str_replace(find:" ", replace:"%20", string:exploit)
    );

    res = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(res)) exit(0);

    # There's a problem if we see an error with our exploit.
    if (
      "error in your SQL syntax" >< res[2] &&
      string("&& blogentry_blogentrycat_id=", exploit) >< res[2]
    )
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to verify the vulnerability exists using the following\n",
          "URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
      exit(0);
    }
  }
}
