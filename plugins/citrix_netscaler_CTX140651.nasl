#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74026);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/12 16:40:05 $");

  script_cve_id("CVE-2014-2881", "CVE-2014-2882");
  script_bugtraq_id(67156, 67160);
  script_osvdb_id(106477, 106478);

  script_name(english:"Citrix NetScaler Multiple Vulnerabilities (CTX140651)");
  script_summary(english:"Checks Citrix NetScaler version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix NetScaler version is affected by multiple
vulnerabilities :

  - A low quality random number generation is used to
    produce secret key values in the implementation
    of the Diffie-Hellman key exchange algorithm in
    the management GUI Java applet. Publicly known
    predictors exist for the random number
    generator used and the seed value is only 32
    or 48 bits. (CVE-2014-2881)

  - The certificate validation component of the management
    GUI allows any certificate to be used, regardless of
    validity, due to assigning an empty trust manager to
    its SSL context. (CVE-2014-2882)");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX140651");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532041/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532042/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Citrix NetScaler 10.1-122.17 or 9.3-66.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/15");

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

if (!build)
  exit(0, "The build number of " + app_name + " " + version + " could not be determined.");

display_version = version + "-" + build;
version = version + "." + build;

enhanced = get_kb_item("Host/NetScaler/Enhanced");
if (enhanced) audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version + ".e");

if (version =~ "^10\.")
{
  # 10+
  fixed_version = "10.1.122.17";
}
else
{
  # < 10
  fixed_version  = "9.3.66.5";
}

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) >= 0) audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);

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
