#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78510);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/28 14:01:58 $");

  script_cve_id("CVE-2014-7299");
  script_osvdb_id(112832);

  script_name(english:"ArubaOS 6.3.1.11 / 6.4.2.1 SSH Authentication Bypass");
  script_summary(english:"Checks the ArubaOS version.");

  script_set_attribute(attribute:"synopsis", value:"The version of ArubaOS has an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ArubaOS has an unspecified vulnerability that allows a
remote attacker to obtain limited administrative privileges without
valid credentials. The vulnerability affects access over SSH. However,
access through WebUI and the serial port is not affected, and the
vulnerability does not provide 'root' level access, although it could
allow the following activities :

  - Issue 'show' commands.

  - Obtain encrypted password hashes for administrative
    accounts.

  - View the running configuration.

  - Add users to the internal user database with 'guest'
    rights.");
  script_set_attribute(attribute:"see_also", value:"http://www.arubanetworks.com/assets/alert/aid-10072014.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to 6.3.1.12 / 6.4.2.2  or downgrade to 6.3.1.10 / 6.4.2.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("arubaos_detect.nbin");
  script_require_keys("Host/ArubaNetworks/ArubaOS/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/ArubaNetworks/ArubaOS/version");

# Version may contain -FIPS at the end, unable to verify
chkvers = ereg_replace(pattern:"-FIPS", replace:"", string:version);

fixed = FALSE;
if (chkvers == "6.4.2.1")       fixed = "6.4.2.2";
else if (chkvers == "6.3.1.11") fixed = "6.3.1.12";
if ("FIPS" >< version && fixed) fixed += "-FIPS";

if (fixed)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+fixed+
      '\n';
    security_hole(port:0,extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_DEVICE_NOT_VULN, "ArubaOS device", version);
