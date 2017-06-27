#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56413);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/16 11:00:59 $");

  script_cve_id("CVE-2011-0794", "CVE-2011-0808", "CVE-2011-2264");
  script_bugtraq_id(47435, 47437, 48766);
  script_osvdb_id(71969, 71970, 73913);
  script_xref(name:"CERT", value:"103425");
  script_xref(name:"CERT", value:"520721");

  script_name(english:"Symantec Enterprise Vault / Oracle Outside In Multiple Vulnerabilities (SYM11-011)");
  script_summary(english:"Checks SEV Version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An archiving application installed on the remote host has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Symantec Enterprise Vault installed on the remote host
uses a version of the Oracle Outside In libraries that contain
multiple memory corruption vulnerabilities.  A remote attacker could
exploit these by sending an email with a malicious attachment, which
could result in arbitrary code execution when it is processed for
archiving."
  );
  # http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2011&suid=20110901_00
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?dff70b04");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant hotfix referenced in SYM11-011.  

Note that versions earlier than 8.0.5 must be upgraded to 8.0.5 before
the hotfix can be applied."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-407");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:symantec:enterprise_vault");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("symantec_enterprise_vault_installed.nasl");
  script_require_keys("SMB/enterprise_vault/path", "SMB/enterprise_vault/ver");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/enterprise_vault/path");
ver = get_kb_item_or_exit("SMB/enterprise_vault/ver");

match = eregmatch(string:ver, pattern:"^([0-9.]+)\.([0-9]+)$");
if (isnull(match))
  exit(1, "Error parsing version ('" + ver + "').");
else
  display_ver = match[1] + ' build ' + match[2];

if (ver_compare(ver:ver, fix:'8.0.5.1076', strict:FALSE) == -1)
  display_fix = '8.0.5 build 1076';
else if (ver =~ "^9\.0\.0\." && ver_compare(ver:ver, fix:'9.0.0.1248', strict:FALSE) == -1)
  display_fix = '9.0.0 build 1248';
else if (ver =~ "^9\.0\.1\." && ver_compare(ver:ver, fix:'9.0.1.1107', strict:FALSE) == -1)
  display_fix = '9.0.1 build 1107';
else if (ver =~ "^9\.0\.2\." && ver_compare(ver:ver, fix:'9.0.2.1175', strict:FALSE) == -1)
  display_fix = '9.0.2 build 1175';
else if (ver =~ "^10\.0\.0\." && ver_compare(ver:ver, fix:'10.0.0.1323', strict:FALSE) == -1)
  display_fix = '10.0.0 build 1323';
else
  exit(0, 'Symantec Enterprise Vault version ' + ver + ' is installed and therefore not affected.');

port = get_kb_item('SMB/transport');

if (report_verbosity > 0)
{
  report = 
    '\n  Path              : ' + path +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + display_fix + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
