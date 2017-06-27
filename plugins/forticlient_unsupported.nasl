#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(93098);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/08/24 20:39:56 $");

  script_name(english:"Fortinet FortiClient Unsupported Version Detection");
  script_summary(english:"Checks for EOL versions.");

  script_set_attribute(attribute:"synopsis", value:
"An endpoint protection application installed on the remote host is no
longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Fortinet FortiClient on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.fortinet.com/Information/ProductLifeCycle.aspx");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Fortinet FortiClient that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "FortiClient";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
path     = install['path'];
version  = install['version'];
supported_versions = "5.0.x / 5.2.x / 5.4.x";

eol_versions =
  make_array(
    "^[0-2]($|\.)", "Unknown",             # 0.x - 2.x - Vendor didn't publish EOL
    "^3\.[0-3]($|\.)", "Unknown",          # 3.0 - 3.3 - Vendor didn't publish EOL
    "^3\.4($|\.)", "January 31, 2010",
    "^3\.5($|\.)", "June 18, 2010",
    "^3\.6($|\.)", "February 8, 2011",
    "^3\.7($|\.)", "August 12, 2011",
    "^3\.8($|\.)", "June 22, 2013",
    "^4\.0($|\.)", "January 23, 2012",
    "^4\.1($|\.)", "September 2, 2012",
    "^4\.2($|\.)", "May 14, 2013",
    "^4\.3($|\.)", "June 8, 2014"
  #  "^5\.0($|\.)", "May 2, 2017",
  #  "^5\.2($|\.)", "December 16, 2018",
  #  "^5\.4($|\.)", "April 9, 2020",
  );


port = get_kb_item("SMB/transport");
if (!port) port = 445;

foreach eol (keys(eol_versions))
{
  if (version =~ eol)
  {
    register_unsupported_product(product_name:"FortiClient Endpoint Protection",
                                 cpe_base:"fortinet:forticlient", version:version);
    report =
      '\n  Path                       : ' + path +
      '\n  Installed version          : ' + version +
      '\n  Supported versions         : ' + supported_versions +
      '\n  EOL date                   : ' + eol_versions[eol] +
      '\n  EOL URL (account required) : https://support.fortinet.com/Information/ProductLifeCycle.aspx' +
      '\n';
    security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
    exit(0);
  }
}
audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
