#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97470);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/03/01 21:10:12 $");

  script_name(english:"Cisco Identity Services Engine (ISE) Unsupported Version Detection");
  script_summary(english:"Checks the Cisco ISE version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Cisco ISE running on the remote host is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Cisco Identity Services Engine (ISE) on the remote host is no longer
supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # http://www.cisco.com/c/en/us/products/security/identity-services-engine/eos-eol-notice-listing.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b4d5068");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Cisco ISE that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname   = "Cisco ISE";
version   = get_kb_item_or_exit('Host/Cisco/ISE/version');
supported = '1.2 / 1.3 / 1.4 / 2.0 / 2.1 / 2.2';

eol = make_array();

eol['1.0']['Date'] = "2015/04/06";
eol['1.0']['URL']  = "http://www.cisco.com/c/en/us/products/collateral/security/identity-services-engine/eos-eol-notice-c51-734275.html";

eol['1.1']['Date'] = "2015/04/06";
eol['1.1']['URL']  = "http://www.cisco.com/c/en/us/products/collateral/security/identity-services-engine/eos-eol-notice-c51-734276.html";

#eol['1.2']['Date'] = "2017/05/31";
#eol['1.2']['URL']  = "http://www.cisco.com/c/en/us/products/collateral/security/identity-services-engine/eos-eol-notice-c51-736297.html";

#eol['1.3']['Date'] = "2017/12/31";
#eol['1.3']['URL']  = "http://www.cisco.com/c/en/us/products/collateral/security/identity-services-engine/bulletin-c25-737392.html";

ver_split = split(version, sep:'.', keep:FALSE); 
release = ver_split[0] + "." + ver_split[1];

# version 0.x isn't listed on Cisco's ISE EOL page but if it exists it's presumably unsupported
if (version =~ "^0\.")
  eol_date = 'unknown';
else
  eol_date = eol[release]['Date'];

if (isnull(eol_date)) audit(AUDIT_INST_VER_NOT_VULN, appname, version);

register_unsupported_product(product_name:appname, cpe_base:"cisco:identity_services_engine", version:version);

report =
  '\n  Installed version : ' + version +
  '\n  Latest versions   : ' + supported +
  '\n  EOL date          : ' + eol_date +
  '\n  EOL URL           : ' + eol[release]['URL'] +
  '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
