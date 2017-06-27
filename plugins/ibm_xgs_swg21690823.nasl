#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80335);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/13 20:14:28 $");

  script_cve_id("CVE-2014-6183");
  script_bugtraq_id(71258);
  script_osvdb_id(114863);

  script_name(english:"IBM Network Security Protection XGS Remote Code Execution (swg21690823) (credentialed check)");
  script_summary(english:"Checks version and patch information.");

  script_set_attribute(attribute:"synopsis", value:
"The remote appliance has an application that is affected by a code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The firmware version installed on the remote IBM XGS appliance does
not properly sanitize certain user-supplied inputs which can allow a
remote, authenticated attacker to execute shell commands with the
privileges of the 'www-data' user via a standard HTTP request.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21690823");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:security_network_protection_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ibm_xgs_webui_detect.nbin");
  script_require_keys("Host/IBM/XGS/version");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");

version = get_kb_item_or_exit("Host/IBM/XGS/version");
if(version == "unknown")
  audit(AUDIT_UNKNOWN_DEVICE_VER,"IBM Network Security Protection firmware");
patches = get_kb_item("Host/IBM/XGS/patches");
if(isnull(patches) && report_paranoia < 2)
  audit(AUDIT_KB_MISSING,"Host/IBM/XGS/patches");

if(isnull(patches))
  patches = "";

reqpatch = FALSE;
if(version =~ "^5\.1$")
  reqpatch = make_list("5.1.0.0-ISS-XGS-All-Models-Hotfix-FP0013");
else if(version =~ "^5\.1\.0")
  reqpatch = make_list("5.1.0.0-ISS-XGS-All-Models-Hotfix-FP0013");
else if(version =~ "^5\.1\.1\.")
  reqpatch = make_list("5.1.1.0-ISS-XGS-All-Models-Hotfix-FP0008");
else if(version =~ "^5\.1\.2(\.0|$)")
  reqpatch = make_list("5.1.2.0-ISS-XGS-All-Models-Hotfix-FP0009");
else if(version =~ "^5\.1\.2\.1$")
  reqpatch = make_list("5.1.2.1-ISS-XGS-All-Models-Hotfix-FP0005");
else if(version =~ "^5\.3(\.0|$)")
  reqpatch = make_list("5.3.0.0-ISS-XGS-All-Models-Hotfix-FP0001");
else if(version =~ "^5\.2(\.0|$)")
{
  reqpatch = make_list(
    "5.2.0.0-ISS-XGS-All-Models-Hotfix-FP0005",
    "5.2.0.0-ISS-XGS-All-Models-Hotfix-IF0005"
  );
}

# Unmentioned version, assume not vulnerable
if(!reqpatch)
  audit(AUDIT_DEVICE_NOT_VULN,"IBM Network Security Protection XGS",version);

# Check for patch
foreach patch (reqpatch)
{
  if(patch >< patches)
    audit(AUDIT_PATCH_INSTALLED, patch, "IBM Network Security Protection XGS", version);
}

port = get_http_port(default:443);
if (report_verbosity > 0)
{
  reqpatch = reqpatch[0];
  report =
    '\n  Firmware version    : ' + version +
    '\n  Required patch      : ' + reqpatch;
  security_hole(port:port, extra:report+'\n');
}
else security_hole(port:port);
