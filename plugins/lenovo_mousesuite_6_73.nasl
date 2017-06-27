#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85908);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/14 13:50:03 $");

  script_cve_id("CVE-2015-4596");
  script_osvdb_id(126589);

  script_name(english:"Lenovo Mouse Suite < 6.73 Local Privilege Elevation");
  script_summary(english:"Checks the file version of Lenovo Mouse Suite.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
a local privilege elevation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Lenovo Mouse Suite installed on the remote Windows host
is prior to 6.73. It is, therefore, affected by a privilege elevation
vulnerability that can allow a local attacker to gain administrative
privileges on the system.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.lenovo.com/us/en/product_security/len_2015_066");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Lenovo Mouse Suite 6.73 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:lenovo:mouse_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("lenovo_mousesuite_installed.nbin");
  script_require_keys("installed_sw/Lenovo Mouse Suite");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Lenovo Mouse Suite";

install = get_single_install(app_name: app, exit_if_unknown_ver: TRUE);

path = install['path'];
version = install['version'];

fix = "6.73";

# Check for fix, Versions < 6.73 are vulnerable.
if (ver_compare(ver: version, fix: fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
