#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89940);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_osvdb_id(135384);
  script_xref(name:"MCAFEE-SB", value:"SB10151");
  script_xref(name:"EDB-ID", value:"39531");

  script_name(english:"McAfee VirusScan Enterprise < 8.8 Patch 7 Protected Resource Access Bypass (SB10151)");
  script_summary(english:"Checks the version of McAfee VSE.");

  script_set_attribute(attribute:"synopsis", value:
"The antivirus application installed on the remote Windows host is
affected by a security mechanism bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee VirusScan Enterprise (VSE) installed on the
remote Windows host is prior to 8.8 Patch 7. It is, therefore,
affected by a flaw in its self-protection mechanism when applying
rules to access settings, which are used to determine what
applications and associated actions can be trusted. An attacker with
Windows administrative privileges can exploit this flaw to control
the trust settings and bypass access restrictions, allowing protected
McAfee applications, including VSE, to be disabled or uninstalled.

Note that the attacker does not need to possess the management
password to exploit this vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10151");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee VirusScan Enterprise version 8.8 Patch 7.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_installed.nasl");
  script_require_keys("Antivirus/McAfee/installed");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

get_kb_item_or_exit("Antivirus/McAfee/installed");
product_name = get_kb_item_or_exit("Antivirus/McAfee/product_name");
version      = get_kb_item_or_exit("Antivirus/McAfee/product_version");

if ("McAfee VirusScan Enterprise" >!< product_name)
  audit(AUDIT_INST_VER_NOT_VULN, product_name);

fix = '8.8.0.1528';

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  order  = make_list('Installed version', 'Fixed version');
  report = make_array(order[0],version, order[1],fix); 
  report = report_items_str(report_items:report, ordered_fields:order);
  security_report_v4(extra:report, port:port, severity:SECURITY_NOTE);
}
else audit(AUDIT_INST_VER_NOT_VULN, product_name, version);
