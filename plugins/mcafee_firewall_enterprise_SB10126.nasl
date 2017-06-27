#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85402);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/21 20:57:10 $");

  script_cve_id("CVE-2015-5477");
  script_bugtraq_id(76092);
  script_osvdb_id(125438);
  script_xref(name:"IAVB", value:"2015-B-0099");
  script_xref(name:"MCAFEE-SB", value:"SB10126");

  script_name(english:"McAfee Firewall Enterprise DoS (SB10126)");
  script_summary(english:"Checks the version of MFE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee Firewall Enterprise installed
that is affected by a denial of service vulnerability due to an
assertion flaw that occurs when handling TKEY queries. A remote
attacker can exploit this, via a specially crafted request, to cause a
REQUIRE assertion failure and daemon exit, resulting in a denial of
service condition.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10126");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor security
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:mcafee:firewall_enterprise");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

patchmap = make_array(
  "^7\."               , make_list("70103E76"),
  "^8\.3\.[0-1](\.|$)" , make_list("8.3.1E81"),
  "^8\.3\.2(\.|$)"     , make_list("8.3.2E61")
);

fix_displays = make_array(
  "^7\."               , "70103E76",
  "^8\.3\.[0-1](\.|$)" , "8.3.1 ePatch 81",
  "^8\.3\.2(\.|$)"     , "8.3.2 ePatch 61"
);

patches       = NULL;
fix_display   = NULL;
patch_missing = TRUE;

# Find our patch information
foreach vergx (keys(patchmap))
{
  if(version =~ vergx)
  {
    patches     = patchmap[vergx];
    fix_display = fix_displays[vergx];
    break;
  }
}

if(isnull(patches))
  audit(AUDIT_INST_VER_NOT_VULN, version_display);

# Check for patches that fix the issue
foreach patch (patches)
{
  if(patch >< installed_patches)
  {
    patch_missing = FALSE;
    break;
  }
}

if (patch_missing)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version_display +
      '\n  Patched version   : ' + fix_display +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_PATCH_INSTALLED, fix_display, app_name);
