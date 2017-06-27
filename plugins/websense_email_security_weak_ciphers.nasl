#
# (C) Tenable Network Security, 
#

include("compat.inc");

if (description)
{
  script_id(69517);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2012-4605");
  script_bugtraq_id(59313);
  script_osvdb_id(85101);
  script_xref(name:"IAVB", value:"2013-B-0040");

  script_name(english:"Websense Email Security SMTP Component Weak SSL/TLS Ciphers");
  script_summary(english:"Checks version of Websense Email Security");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an email security application installed that is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Websense Email Security installed on the remote
Windows host is earlier than 7.3 hotfix 6. As such, it is potentially
affected by an information disclosure vulnerability.  The application
could use a weak SSL cipher suite, which could allow an attacker to 
obtain potentially sensitive information."); 
  # http://www.websense.com/support/article/kbarticle/SSL-TLS-weak-and-export-ciphers-detected-in-Websense-Email-Security-deployments
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d904d284");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Websense Email Security 7.3 hotfix 6 and configure the
SSLCipherSuite registry key as discussed in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:websense:websense_email_security");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("websense_email_security_installed.nasl");
  script_require_keys("SMB/Websense Email Security/Path", "SMB/Websense Email Security/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

port = kb_smb_transport();

version = get_kb_item_or_exit('SMB/Websense Email Security/Version');
path = get_kb_item_or_exit('SMB/Websense Email Security/Path');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\SurfControl plc\SuperScout Email Filter\SMTP\SSLCipherSuite";
ciphersuite = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);
NetUseDel();

if (version =~ '^(6\\.1\\.|7\\.[0-2]\\.)' || (version  =~ '^7\\.3\\.' && ver_compare(ver:version, fix:'7.3.0.1192') < 0))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.3.0.1192\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
  exit(0);
}
else
{
  if (isnull(ciphersuite) || ciphersuite == '')
  {
    if (report_verbosity > 0)
    {
      report =
        '\nThe SSLCipherSuite registry key has not been configured as instructed' +
        '\nin the advisory.';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  audit(AUDIT_INST_PATH_NOT_VULN, 'Websense Email Security', version, path);
}
