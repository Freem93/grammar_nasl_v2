#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83735);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/21 20:57:10 $");

  script_cve_id("CVE-2015-1414");
  script_bugtraq_id(72777);
  script_osvdb_id(118734);
  script_xref(name:"MCAFEE-SB", value:"SB10107");

  script_name(english:"McAfee Firewall Enterprise IGMP Packet Integer Overflow DoS (SB10107)");
  script_summary(english:"Checks the version of MFE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee Firewall Enterprise installed
that is affected by an integer overflow condition. An unauthenticated,
remote attacker, by sending a specially crafted IGMP packet, can cause
the application to crash due to allocation of insufficient memory.  An
incomplete fix was offered in 8.3.2 ePatch 41, 8.3.1 ePatch 70 and
8.2.1 ePatch 135 but newer patches have been released to fully address
the issue.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10107");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor security
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:mcafee:firewall_enterprise");

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
  "^8\.2\.1(\.|$)"       , make_list("8.2.1E138"),
  "^8\.3\.[0-1](\.|$)"   , make_list("8.3.1E73"),
  "^8\.3\.2(\.|$)"       , make_list("8.3.2E45","8.3.2P07")
);

fix_displays = make_array(
  "^8\.2\.1(\.|$)"     , "8.2.1 ePatch 138",
  "^8\.3\.[0-1](\.|$)" , "8.3.1 ePatch 73",
  "^8\.3\.2(\.|$)"     , "8.3.2 ePatch 45 or Patch 7"
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
      '\n  Installed Version : ' + version_display +
      '\n  Patched Version   : ' + fix_display +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_PATCH_INSTALLED, fix_display, app_name);
