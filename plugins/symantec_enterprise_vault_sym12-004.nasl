#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58514);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/03/08 15:07:21 $");

  script_cve_id("CVE-2012-0110", "CVE-2011-4516", "CVE-2011-4517");
  script_bugtraq_id(50992, 51452);
  script_osvdb_id(77595, 77596, 78411);
  script_xref(name:"CERT", value:"738961");
  script_xref(name:"CERT", value:"887409");

  script_name(english:"Symantec Enterprise Vault / Oracle Outside In Multiple Vulnerabilities (SYM12-004)");
  script_summary(english:"Checks version of EVConverterSandbox.exe.");

  script_set_attribute(attribute:"synopsis", value:
"An archiving application installed on the remote host has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Enterprise Vault installed on the remote host
uses a version of the Oracle Outside In libraries that contain
multiple memory corruption vulnerabilities. A remote attacker could
exploit these by sending an email with a malicious attachment, which
could result in arbitrary code execution when it is processed for
archiving.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eef96c2a");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11da589e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix referenced in SYM12-004.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:symantec:enterprise_vault");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("symantec_enterprise_vault_installed.nasl");
  script_require_keys("SMB/enterprise_vault/path", "SMB/enterprise_vault/ver");

  exit(0);
}

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

if (ver =~ "^9\.0\.0\.")
  fix = "9.0.0.1257";
else if (ver =~ "^9\.0\.1\.")
  fix = "9.0.1.1112";
else if (ver =~ "^9\.0\.2\.")
  fix = "9.0.2.1218";
else if (ver =~ "^9\.0\.3\.")
  fix = "9.0.3.1222";
else if (ver =~ "^10\.0\.0\.")
  fix = "10.0.0.1334";

if (!isnull(fix) && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + pretty(ver) +
      '\n  Fixed version     : ' + pretty(fix) +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The Symantec Enterprise Vault " + ver + " install in "+path+" is not affected.");
