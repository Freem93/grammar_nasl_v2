#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93227);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/09/08 17:01:32 $");

  script_name(english:"Microsoft Office Compatibility Pack Unsupported Version Detection");
  script_summary(english:"Checks the Office viewer versions.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Microsoft Office Compatibility Pack installed on the
remote host is no longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported component version numbers, the
installation of Microsoft Office Compatibility Pack on the remote host
is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
# https://support.microsoft.com/en-us/help/17138/service-pack-support-lifecycle-policy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69810b65");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Office Compatibility Pack that is
currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("microsoft_office_compatibility_pack_installed.nbin");
  script_require_keys("installed_sw/Microsoft Office Compatibility Pack");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name     = "Microsoft Office Compatibility Pack";

# Initialize supported_info array

# Main Office Compatibility Pack installation SP level is determined by the
# component SP levels, so it doesn't have a specific file version
supported_info[app_name]['2007']['supported_sp']         = 3;

supported_info['WordCnv']['2007']['supported_sp']        = 3;
supported_info['WordCnv']['2007']['supported_ver']       = "12.0.6500.5000";

supported_info['ExcelCnv']['2007']['supported_sp']       = 3;
supported_info['ExcelCnv']['2007']['supported_ver']      = "12.0.6611.1000";

supported_info['PowerPointCnv']['2007']['supported_sp']  = 3;
supported_info['PowerPointCnv']['2007']['supported_ver'] = "12.0.6500.5000";

### Main

components  = make_list("WordCnv", "ExcelCnv", "PowerPointCnv");
report_info = make_array();

# Look for unsupported Office Compatibility Pack in general first, since its
# Service Pack level is based on the lowest Converter Service Pack level

installs = get_installs(app_name:app_name, exit_if_not_found:TRUE);
foreach install (installs[1])
{
  product = install['version'];
  if(isnull(product)) continue;

  sp      = install['Service Pack'];

  supported_sp      = supported_info[app_name][product]['supported_sp'];

  supported_version_text = "";
  caveat                 = "";

  if (supported_sp < 0)
    supported_version_text = "This version is no longer supported.";
  else if (!isnull(sp) && int(sp) < supported_sp)
    supported_version_text = product + " SP" + supported_sp;

  if (empty_or_null(supported_version_text)) continue;

  if (int(sp) > 0)
    verbose_version = product + " SP" + sp;
  else
    verbose_version = product;

  report_info[product]['sp']         = sp;
  report_info[product]['main_info'] +=
    '\n  Path                      : ' + install['path'] +
    '\n  Installed version         : ' + verbose_version +
    '\n  Minimum supported version : ' + supported_version_text +
    '\n' + caveat;
}

if (max_index(keys(report_info)) < 1)
  audit(AUDIT_HOST_NOT, "affected");

foreach component (components)
{
  installs = get_installs(app_name:component, exit_if_not_found:FALSE);
  if (max_index(keys(installs)) == 0) continue;

  foreach install (installs[1])
  {
    product = install['Product'];
    sp      = install['Service Pack'];
    version = install['version'];

    supported_sp      = supported_info[component][product]['supported_sp'];
    supported_version = supported_info[component][product]['supported_ver'];

    supported_version_text = "";
    if (supported_sp < 0)
      supported_version_text = "This version is no longer supported.";
    else if (!isnull(sp) && int(sp) < supported_sp)
      supported_version_text = supported_version + " (" + product + " SP" + supported_sp + ")";

    if (empty_or_null(supported_version_text)) continue;

    if (int(sp) > 0)
      verbose_version = version + " (" + product + " SP" + sp + ")";
    else
      verbose_version = version + " (" + product + ")";

    report_info[product]['info'] +=
      '\n    Path : ' + install['path'] +
      '\n      Component                 : ' + install['Display Name'] +
      '\n      Installed version         : ' + verbose_version +
      '\n      Minimum supported version : ' + supported_version_text +
      '\n';

    report_info[product]['vuln'] = report_info[product]['vuln'] + 1;
  }
}

if (max_index(keys(report_info)) < 1)
  audit(AUDIT_HOST_NOT, "affected");

if(max_index(keys(report_info)) > 1) s = 's were';
else s = ' was';

report =
  '\nThe following unsupported Microsoft Office Compatibility Pack installation' + s +
  '\nfound on the remote host :' +
  '\n';

foreach product(keys(report_info))
{
  report += report_info[product]['main_info'];

  if (report_info[product]['vuln'] > 1) s = 's have';
  else s = ' has';

  report +=
    '\n    The following component' + s + ' an unsupported file version :' +
    '\n' + report_info[product]['info'] +
    '\n';

  sp = report_info[product]['sp'];
  if (!isnull(sp) && int(sp) > 0)
    product += " SP" + sp;

  register_unsupported_product(product_name:app_name, version:product,
                               cpe_base:'microsoft:office_compatibility_pack');
}

port = get_kb_item("SMB/transport");
if (!port) port = 445;

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
