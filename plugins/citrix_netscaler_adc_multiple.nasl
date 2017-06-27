#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73205);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/12 16:40:05 $");

  script_cve_id(
    "CVE-2012-2141",
    "CVE-2013-6938",
    "CVE-2013-6939",
    "CVE-2013-6940",
    "CVE-2013-6941",
    "CVE-2013-6942",
    "CVE-2013-6943",
    "CVE-2013-6944"
  );
  script_bugtraq_id(
    53255,
    66008,
    66010,
    66013,
    66014,
    66018,
    66020,
    66043
  );
  script_osvdb_id(
    81636,
    104092,
    104096,
    104097,
    104098,
    104099,
    104100,
    104102
  );

  script_name(english:"Citrix NetScaler Application Delivery Controller Multiple Vulnerabilities");
  script_summary(english:"Checks Citrix NetScaler version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix NetScaler version is affected by multiple
vulnerabilities :

  - A denial of service vulnerability in the VM Virtual
    Machine Daemon. Please note that this particular
    vulnerability does not apply to Citrix NetScaler 10.1.
    (CVE-2013-6938)

  - A denial of service vulnerability in the Application
    Delivery Controller RADIUS authentication.
    (CVE-2013-6939)

  - An authenticated denial of service in the SNMP
    daemon. (CVE-2012-2142)

  - An unspecified authentication disclosure in the
    Application Delivery Controller. (CVE-2013-6940)

  - An unspecified shell breakout in the Application
    Delivery Controller firmware. (CVE-2013-6941)

  - An unspecified LDAP username injection vulnerability
    in the Application Delivery Controller.
    (CVE-2013-6943)

  - A cross-site scripting vulnerability in the AAA TM
    vServer user interface. (CVE-2013-6944)");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX139049");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX140113");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix NetScaler 10.1-118.7 / 10.0-77.5 / 9.3-64.4 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:citrix:netscaler_application_delivery_controller_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Citrix NetScaler";
version = get_kb_item_or_exit("Host/NetScaler/Version");
build = get_kb_item("Host/NetScaler/Build");

if (!build) exit(0, "The build number of " + app_name + " " + version + " could not be determined.");

display_version = version + "-" + build;
version = version + "." + build;

enhanced = get_kb_item("Host/NetScaler/Enhanced");
if (enhanced) audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version + ".e");

if (version =~ "^9\.3\.")
{
  # 9.3
  fixed_version = "9.3.64.4";
}
else if (version =~ "^10\.0\.")
{
  # 10.0
  fixed_version = "10.0.77.5";
}
else if (version =~ "^10\.1\.")
{
  # 10.1
  fixed_version = "10.1.118.7";
}
else
{
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
}

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  set_kb_item(name:"www/0/XSRF", value:TRUE);

  if (report_verbosity > 0)
  {
    display_fixed = ereg_replace(string:fixed_version, pattern:"^([0-9]+\.[0-9]+)\.(.*)$", replace:"\1-\2");
    report =
      '\n  Installed version : ' + display_version +
      '\n  Fixed version     : ' + display_fixed +
      '\n';
    security_hole(extra:report, port:0);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
