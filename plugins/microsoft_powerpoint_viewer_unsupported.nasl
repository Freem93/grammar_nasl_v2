#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93228);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/09/08 17:01:32 $");

  script_name(english:"Microsoft PowerPoint Viewer Unsupported Version Detection");
  script_summary(english:"Checks the PowerPoint Viewer version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Microsoft PowerPoint Viewer installed on the remote
host is no longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Microsoft PowerPoint Viewer on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

Note that PowerPoint Viewer was formerly known as PowerPoint Viewer
2010. The file versions are the same, only the name has changed in
references to the product.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/979860");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft PowerPoint Viewer that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_viewer");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("microsoft_powerpoint_viewer_installed.nbin");
  script_require_keys("installed_sw/Microsoft PowerPoint Viewer");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Microsoft PowerPoint Viewer";
port     = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_installs(app_name:app_name, port:port, exit_if_not_found:TRUE);
cpe      = "microsoft:powerpoint_viewer";

# Initialize supported_info array

supported_info['2010']['supported_sp']             = 2;
supported_info['2010']['supported_ver']            = "14.0.7015.1000";
supported_info['2007']['supported_sp']             = 3;
supported_info['2007']['supported_ver']            = "12.0.6600.1000";
supported_info['2003']['supported_sp']             = -1;
supported_info['97 / 2000 / 2002']['supported_sp'] = -1;

### Main

info = '';
vuln = 0;

foreach install(installs[1])
{
  product = install['Product'];
  if(isnull(product)) continue;

  path       = install['path'];
  sp         = install['sp'];
  version    = install['version'];
  display_sp = install['Service Pack'];

  supported_sp      = supported_info[product]['supported_sp'];
  supported_version = supported_info[product]['supported_ver'];

  supported_version_text = "";
  if (supported_sp < 0)
    supported_version_text = "This version is no longer supported.";
  else if (!isnull(sp) && int(sp) < supported_sp)
    supported_version_text = supported_version + " (" + product + " SP" + supported_sp + ")";

  if (empty_or_null(supported_version_text)) continue;

  if (sp != UNKNOWN_VER && !empty_or_null(sp))
    verbose_version = version + " (" + product + " " + display_sp + ")";
  else
    verbose_version = version + " (" + product + ")";

  register_unsupported_product(product_name:app_name, version:version,
                               cpe_base:cpe);

  info += '\n  Path                      : ' + path +
          '\n  Installed version         : ' + verbose_version +
          '\n  Minimum supported version : ' + supported_version_text +
          '\n';
  vuln++;
}

if (vuln == 0)
  audit(AUDIT_HOST_NOT, "affected");

if (vuln > 1) s = 's were';
else s = ' was';

report +=
  '\n' + 'The following unsupported ' + app_name + ' installation' + s + ' detected on' +
  '\n' + 'the remote host :' +
  '\n' + info +
  '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
