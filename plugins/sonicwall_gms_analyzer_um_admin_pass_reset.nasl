#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95656);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/12 14:40:36 $");

  script_osvdb_id(147958); 
  script_xref(name:"TRA", value:"TRA-2016-37");

  script_name(english:"Dell SonicWALL Global Management System (GMS) / Analyzer Universal Management Appliance or Host (UMA / UMH) Information Disclosure");
  script_summary(english:"Resets admin password with wrong key.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Dell SonicWALL Global Management System (GMS) / Analyzer running
on the remote host is affected by an information disclosure
vulnerability due to a failure to protect access to the
/appliance/license.jsp script. An unauthenticated, remote attacker can
exploit this issue to easily compute the pwdResetKey, which can then
be used by the attacker to reset the password of the user 'admin' to
'password', resulting in gaining full administrative access to the
Universal Management Appliance (UMA) or the Universal Management Host
(UMH) interface.

Note that GMS / Analyzer is reportedly affected by other 
vulnerabilities as well; however, Nessus has not tested for these.");
  # http://documents.software.dell.com/sonicwall-gms-os/8.2/release-notes/resolved-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43d2d4be");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/research/tra-2016-37");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SonicWALL Global Management System (GMS) / Analyzer version
8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:sonicwall_global_management_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:sonicwall_analyzer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("sonicwall_universal_management_detect.nbin");
  script_require_keys("dell/sonicwall/universal_management");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

get_kb_item_or_exit("dell/sonicwall/universal_management"); 

port = get_http_port(default:80);

get_kb_item_or_exit("dell/sonicwall/universal_management/" + port); 

# Invalid pwdResetKey
prk = 'AAAAAAAAAAAAAAAAAAAAAA==';

data = "action=resetPwd&pwdResetKey=" + prk;
res = http_send_recv3(
        port        : port, 
        method      : 'POST',
        item        : '/appliance/applianceMainPage',
        data        : data,
        content_type: 'application/x-www-form-urlencoded',
        exit_on_fail: TRUE
      );
# Patched UMA/UMH uses a pwdResetkey obtained from
# LicenseMangager at vendor site. 
if ('Password reset operation failed. Key was not obtained' >< res[2])
{
  audit(AUDIT_HOST_NOT, 'affected');
}
# Vulnerable UMA/UMH uses a pwdResetKey computed from the serial number 
else if ('Password reset operation failed. Invalid key specified' >< res[2])
{ 
  req = http_last_sent_request();
  report = 
    'Nessus was able to detect the vulnerability using the following request :' +
    '\n\n' +
    req;

  security_report_v4(
    port      : port,
    severity  : SECURITY_WARNING,
    extra     : report 
  ); 
} 
else
{
  audit(AUDIT_RESP_BAD, port, 'an admin password reset request'); 
}
  
