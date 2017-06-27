#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11606);
  script_version ("$Revision: 1.21 $");
  script_bugtraq_id(7257);
  script_osvdb_id(5737);

  script_name(english:"WebLogic Crafted GET Request Hostname Disclosure");
  script_summary(english:"Make a request like GET . \r\n\r\n");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote WebLogic server discloses its NetBIOS host name when it is
issued a request generating a redirection.

An attacker may use this information to better prepare other attacks 
against this host."
  );

  script_set_attribute(
    attribute:'solution',
    value: 'Currently, there are no known upgrades or patches to correct this issue.
Filter requests that start with a "." in a proxy or firewall with URL 
filtering capabilities.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2003/Apr/37'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/02");
 script_cvs_date("$Date: 2016/11/29 20:13:37 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencies("weblogic_detect.nasl");
  script_require_ports("Services/www", 80, 7001);
  script_require_keys("www/weblogic");
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");

appname = "WebLogic";
get_kb_item_or_exit("www/weblogic");
port = get_http_port(default:80);
get_kb_item_or_exit("www/weblogic/" + port + "/installed");

w = http_send_recv_buf(port: port, data: 'GET . HTTP/1.0\r\n\r\n');
if (isnull(w)) audit(AUDIT_RESP_BAD, port);

r = strcat(w[0], w[1], '\r\n', w[2]);

if("WebLogic" >!< r) audit(AUDIT_INST_VER_NOT_VULN, appname);

loc = egrep(string:r, pattern:"^Location");
if(!loc) audit(AUDIT_INST_VER_NOT_VULN, appname);
name = ereg_replace(pattern:"^Location: http://([^/]*)/.*",
  replace:"\1", string:loc);

if(name == loc) audit(AUDIT_INST_VER_NOT_VULN, appname);
if(get_host_name() == name) audit(AUDIT_INST_VER_NOT_VULN, appname);
if(get_host_ip() == name) audit(AUDIT_INST_VER_NOT_VULN, appname);

report = "We determined that the remote host name is : '" + name + "'";

security_warning(port:port, extra:report);
exit(0);

