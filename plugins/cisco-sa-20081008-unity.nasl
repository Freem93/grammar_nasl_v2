#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70170);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2008-3814");
  script_bugtraq_id(31638);
  script_osvdb_id(49063);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsr86943");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20081008-unity");

  script_name(english:"Cisco Unity Remote Administration Authentication Bypass (cisco-sa-20081008-unity)");
  script_summary(english:"Checks version of Cisco Unity.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Cisco Unity on the remote host may be affected by an authentication
bypass vulnerability. 

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number. Additionally,
the coarse nature of the version information Nessus gathered is not
enough to confirm that the application is vulnerable, only that it
might be affected.");
  script_set_attribute(attribute:"solution", value:"Upgrade to 4.2.1ES161 / 5.0ES53 / 7.0ES8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(287);

  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20081008-unity.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_unity_installed.nasl");
  script_require_keys("SMB/Cisco_Unity/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Cisco_Unity/Installed");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "Cisco Unity";

kb_base = "SMB/Cisco_Unity/";
ver = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

if (ver =~ "^4\.2\.1([^0-9]|$)")
  fix = "4.2.1ES161";
else if (ver =~ "^5\.0([^0-9]|$)")
  fix = "5.0ES53";
else if (ver =~ "^7\.0([^0-9]|$)")
  fix = "7.0ES8";
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
