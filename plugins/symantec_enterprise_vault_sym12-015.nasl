#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62458);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id(
    "CVE-2012-1766", 
    "CVE-2012-1767", 
    "CVE-2012-1768", 
    "CVE-2012-1769", 
    "CVE-2012-1770", 
    "CVE-2012-1771", 
    "CVE-2012-1772", 
    "CVE-2012-1773", 
    "CVE-2012-3106", 
    "CVE-2012-3107", 
    "CVE-2012-3108", 
    "CVE-2012-3109", 
    "CVE-2012-3110"
  );
  script_bugtraq_id(
    54497, 
    54500, 
    54504, 
    54506, 
    54511, 
    54531, 
    54536, 
    54541, 
    54543, 
    54546, 
    54548, 
    54550, 
    54554
  );
  script_osvdb_id(
    83900, 
    83901, 
    83902, 
    83903, 
    83904, 
    83905, 
    83906, 
    83907, 
    83908, 
    83909, 
    83910,
    83911, 
    83944
  );
  script_xref(name:"CERT", value:"118913");

  script_name(english:"Symantec Enterprise Vault < 10.0.2 Multiple Vulnerabilities in Oracle Outside-In Libraries (SYM12-015)");
  script_summary(english:"Checks version of EVConverterSandbox.exe");

  script_set_attribute(attribute:"synopsis", value:
"An archiving application installed on the remote host has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Enterprise Vault installed on the remote host
uses a version of the Oracle Outside-In libraries that contains multiple
vulnerabilities.  A remote attacker could send an email with a malicious
attachment to be downloaded and stored in a user's mail box until
processed for archiving thus potentially resulting in a denial of
service in the application or allow arbitrary code execution.");
  # http://www.oracle.com/technetwork/topics/security/cpujul2012-392727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd39edea");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120928_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f77792c5");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Enterprise Vault version 10.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-497");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:symantec:enterprise_vault");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_enterprise_vault_installed.nasl");
  script_require_keys("SMB/enterprise_vault/path", "SMB/enterprise_vault/ver");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

function pretty()
{
  local_var match, ver;

  ver = _FCT_ANON_ARGS[0];

  match = eregmatch(string:ver, pattern:"^([0-9.]+)\.([0-9]+)$");
  if (isnull(match))
    exit(1, "Error parsing version ('" + ver + "').");

  return match[1] + " build " + match[2];
}

path = get_kb_item_or_exit("SMB/enterprise_vault/path");
ver = get_kb_item_or_exit("SMB/enterprise_vault/ver");

pretty_ver = pretty(ver);
fix = "10.0.2.1112";

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + pretty_ver +
      '\n  Fixed version     : ' + pretty(fix) +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Symantec Enterprise Vault", pretty_ver, path);
