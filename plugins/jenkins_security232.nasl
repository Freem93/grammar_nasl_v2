#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89725);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/28 13:53:41 $");

  script_cve_id("CVE-2016-0788");
  script_bugtraq_id(83715);
  script_osvdb_id(135041);

  script_name(english:"Jenkins < 1.642.2 / 1.650 Java Object Deserialization RCE");
  script_summary(english:"Checks the Jenkins version, and if necessary, tests if the CLI port is enabled.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Jenkins or Jenkins Enterprise
that is prior to 1.642.2 or 1.650. It is, therefore, affected by a
Java deserialization vulnerability. An unauthenticated, remote
attacker can exploit this, by deserializing specific java.rmi and
sun.rmi objects, to start a JRMP listener on the server. The JRMP
listener can then be exploited over RMI using objects in the Groovy or
Apache Commons Collections libraries, resulting in the execution of
arbitrary code.

Note that the server is reportedly affected by a number of other
vulnerabilities per the Jenkins Security advisory; however, Nessus has
not tested for these.");
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2016-02-24
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93a2c1f1");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2016/q1/461");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jenkins version 1.642.2 / 1.650 or later. Alternatively,
disable the CLI port per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "General");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("jenkins_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/Jenkins");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);
get_kb_item_or_exit("www/Jenkins/"+port+"/Installed");

# LTS has a different version number
is_LTS = get_kb_item("www/Jenkins/"+port+"/is_LTS");
if (is_LTS)
{
  appname = "Jenkins Open Source LTS";
  fixed = "1.642.2";
}
else
{
  appname = "Jenkins Open Source";
  fixed = "1.650";
}

# check the patched versions
version = get_kb_item_or_exit("www/Jenkins/"+port+"/JenkinsVersion");
if (version == "unknown") audit(AUDIT_UNKNOWN_APP_VER, appname);
if (ver_compare(ver: version, fix: fixed, strict: FALSE) >= 0) audit(AUDIT_INST_VER_NOT_VULN, appname, version);

# if the version is less than the patch version then check to see if the CLI port is enabled
url = build_url(qs:'/', port: port);
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (("X-Jenkins-CLI-Port" >!< res[1]) &&
  ("X-Jenkins-CLI2-Port" >!< res[1]) &&
  ("X-Hudson-CLI-Port" >!< res[1])) audit(AUDIT_NOT_DETECT, appname + " CLI");

# Find a CLI port to examine
item = eregmatch(pattern:"X-Jenkins-CLI-Port:\s*([0-9]+)[ \r\n]", string: res[1]);
if (isnull(item))
{
  item = eregmatch(pattern:"X-Hudson-CLI-Port:\s*([0-9]+)[ \r\n]", string: res[1]);
  if (isnull(item))
  {
    item = eregmatch(pattern:"X-Jenkins-CLI2-Port:\s*([0-9]+)[ \r\n]", string: res[1]);
    if (isnull(item)) audit(AUDIT_RESP_BAD, port);
  }
}

# Connect to the CLI port to prove that isn't filtered
cli_port = item[1];
sock = open_sock_tcp(cli_port);
if (!sock) audit(AUDIT_NOT_LISTEN, appname + " CLI", cli_port);
send(socket:sock, data:'\x00\x14Protocol:CLI-connect');
return_val = recv(socket:sock, length:128, min:21);
close(sock);

if (isnull(return_val) || len(return_val) < 21) audit(AUDIT_RESP_BAD, cli_port);
if ("Unknown protocol:" >< return_val) audit(AUDIT_SVC_ERR, cli_port);
else if ('Welcome' >!< return_val) audit(AUDIT_RESP_BAD, cli_port);

report =
    '\n  Port              : ' + cli_port +
    '\n  Product           : ' + appname +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed +
    '\n';
security_report_v4(port:cli_port,severity:SECURITY_HOLE,extra:report);
