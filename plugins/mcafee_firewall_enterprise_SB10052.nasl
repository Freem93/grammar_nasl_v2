#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76118);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/21 20:57:10 $");

  script_cve_id("CVE-2013-4854");
  script_bugtraq_id(61479);
  script_osvdb_id(95707);
  script_xref(name:"MCAFEE-SB", value:"SB10052");

  script_name(english:"McAfee Firewall Enterprise DoS (SB10052)");
  script_summary(english:"Checks version of MFE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee Firewall Enterprise installed
that is affected by a denial of service vulnerability due to a flaw in
the packaged ISC BIND server. An attacker can exploit this by sending
a specially crafted query with a malformed RDATA section.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10052");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-210/");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor security
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:mcafee:firewall_enterprise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("mcafee_firewall_enterprise_version.nbin");
  script_require_keys("Host/McAfeeFE/version", "Host/McAfeeFE/version_display", "Host/McAfeeFE/installed_patches");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "McAfee Firewall Enterprise";
version = get_kb_item_or_exit("Host/McAfeeFE/version");
version_display = get_kb_item_or_exit("Host/McAfeeFE/version_display");
installed_patches = get_kb_item_or_exit("Host/McAfeeFE/installed_patches");
hotfix = "8.3.1E100";
hotfix_display = "8.3.1 ePatch 100";

# Only 8.3.1 is affected. Furthermore, only Patch level 1 and below are affected.
if (version !~ "^8\.3\.1\." || ver_compare(ver:version, fix:"8.3.1.1", strict:FALSE) == 1) audit(AUDIT_INST_VER_NOT_VULN, version_display);

if (hotfix >!< installed_patches)
{
  port = 0;

  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed Version : ' + version_display +
      '\n  Patched Version   : ' + hotfix_display +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_PATCH_INSTALLED, hotfix_display,app_name);
