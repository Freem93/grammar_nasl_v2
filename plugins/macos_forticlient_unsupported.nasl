#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95258);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/11/22 21:41:19 $");

  script_name(english:"Fortinet FortiClient Unsupported Version Detection (macOS)");
  script_summary(english:"Checks for EOL versions.");

  script_set_attribute(attribute:"synopsis", value:
"An endpoint protection application installed on the remote host is no
longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Fortinet FortiClient on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

Note: Login required for Fortinet support page.");
  script_set_attribute(attribute:"see_also", value:"https://support.fortinet.com/Information/ProductLifeCycle.aspx");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Fortinet FortiClient that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macos_forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient (MacOS)");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "FortiClient (macOS)";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
path     = install['path'];
version  = install['version'];
supported_versions = "5.0.x / 5.2.x / 5.4.x";
lowest_supported = "5.0";
date = NULL;

eol_versions =
make_array(
  "^4\.0($|\.)", "June 30, 2014"
#  "^5\.0($|\.)", "May 1, 2017",
#  "^5\.2($|\.)", "December 16, 2018",
#  "^5\.4($|\.)", "April 9, 2020",
);

if(ver_compare(ver:version, fix:lowest_supported, strict:FALSE) < 0)
{
  foreach eol (keys(eol_versions))
  {
    if (version =~ eol)
    {
      date = eol_versions[eol];
    }
  }
  
  if(empty_or_null(date)) date = "Unknown";
  
  register_unsupported_product(product_name:"FortiClient Endpoint Protection", cpe_base:"fortinet:forticlient", version:version);

  order = make_list('Path','Installed version','Supported versions','EOL date', 'EOL URL (account required)');
  report = make_array(
    order[0],path,
    order[1],version,
    order[2],supported_versions,
    order[3],date,
    order[4],'https://support.fortinet.com/Information/ProductLifeCycle.aspx'
    );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
  exit(0);

}
audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
