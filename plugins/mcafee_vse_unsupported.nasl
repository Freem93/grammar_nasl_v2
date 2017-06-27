#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91500);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/06/07 19:22:40 $");

  script_name(english:"McAfee VirusScan Enterprise Unsupported Version Detection");
  script_summary(english:"Checks the version of McAfee VSE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of McAfee VSE.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of McAfee VirusScan
Enterprise (VSE) on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # http://www.mcafee.com/us/support/support-eol.aspx#product=virusscan_enterprise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e6ad7d5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of McAfee VirusScan Enterprise (VSE) that is
currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_installed.nasl");
  script_require_keys("Antivirus/McAfee/installed");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

get_kb_item_or_exit("Antivirus/McAfee/installed");
product_name = get_kb_item_or_exit("Antivirus/McAfee/product_name");
version      = get_kb_item_or_exit("Antivirus/McAfee/product_version");

if ("McAfee VirusScan Enterprise" >!< product_name)
  audit(AUDIT_INST_VER_NOT_VULN, product_name);

# format check
if (version !~ "^\d{1,2}(\.\d|$)") audit(AUDIT_VER_FORMAT, version);
# granularity check
if (version =~ "^8([^0-9\.]|$)") audit(AUDIT_VER_NOT_GRANULAR, product_name, version);

eol_versions =
  make_array(
    "^[0-7](\.[0-9]|$)", make_array(
      'eol_date', 'No Date Available',
      'kb', 'No Announcement Available'
      ),
    "^8\.[0-6]([^0-9]|$)", make_array(
      'eol_date', 'No Date Available',
      'kb', 'No Announcement Available'
      ),
    "^8\.7", make_array(
      'eol_date', 'December 31 2015',
      'kb', 'https://kc.mcafee.com/corporate/index?page=content&id=KB84590'
      )
    );

port = get_kb_item("SMB/transport");
if (!port) port = 445;

foreach eol (keys(eol_versions))
{
  if (version =~ eol)
  {

    register_unsupported_product(
      product_name:product_name, 
      cpe_base:"mcafee:virusscan_enterprise", 
      version:version);

    report =
    '\n  Product           : ' + product_name +
    '\n  Installed version : ' + version +
    '\n  End of life date  : ' + eol_versions[eol]['eol_date'] +
    '\n  EOL announcement  : ' + eol_versions[eol]['kb'] +
    '\n';
    security_report_v4(severity:SECURITY_HOLE, extra:report, port:port);
    exit(0);
  }
}

# If no audit/report by this point, version > latest unsupported.
exit(0, product_name + " " + version + " is still a supported version.");
