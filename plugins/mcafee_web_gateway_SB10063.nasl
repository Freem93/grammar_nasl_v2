#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73137);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2014-2535");
  script_bugtraq_id(66193);
  script_osvdb_id(104111);
  script_xref(name:"MCAFEE-SB", value:"SB10063");

  script_name(english:"McAfee Web Gateway < 7.3.2.6 / 7.4.1 Information Disclosure (SB10063)");
  script_summary(english:"Checks version of MWG");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee Web Gateway prior to
7.3.2.6 / 7.4.1. It is, therefore, affected by an information
disclosure vulnerability. A remote attacker could potentially exploit
this vulnerability to download any file from the device that the user
'mwg' has access to.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10063");
  script_set_attribute(attribute:"solution", value:"Upgrade to 7.3.2.6 / 7.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:web_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_web_gateway_detect.nbin");
  script_require_keys("Host/McAfee Web Gateway/Version", "Host/McAfee Web Gateway/Display Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "McAfee Web Gateway";
version = get_kb_item_or_exit("Host/McAfee Web Gateway/Version");
version_display = get_kb_item_or_exit("Host/McAfee Web Gateway/Display Version");
fix = FALSE;

if (
  version =~ "^7\.2\." ||
  (version =~ "^7\.3\." && version !~ "^7\.3\.2\.5")
)
{
  fix = "7.3.2.6";
  fix_display = "7.3.2.6 Build 16970";
}
else if (version =~ "^7\.4\.")
{
  fix = "7.4.1";
  fix_display = "7.4.1 Build 16854";
}

if (fix && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version_display +
      '\n  Fixed version     : ' + fix_display +
      '\n';
      security_warning(extra:report, port:0);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version_display);
