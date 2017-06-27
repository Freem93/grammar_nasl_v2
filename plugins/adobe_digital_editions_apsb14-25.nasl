#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78679);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/03/13 05:39:55 $");

  script_cve_id("CVE-2014-8068");
  script_osvdb_id(113008);

  script_name(english:"Adobe Digital Editions < 4.0.1 Information Disclosure (APSB14-25)");
  script_summary(english:"Checks version of Adobe Digital Editions");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Digital Editions on the remote Windows host is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Digital Editions installed on the remote host is
is prior to 4.0.1. It is, therefore, affected by an information
disclosure vulnerability due to the transmission of sensitive data in
cleartext.");
  # http://helpx.adobe.com/security/products/Digital-Editions/apsb14-25.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11545739");
  # http://www.adobe.com/solutions/ebook/digital-editions/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3aa2f29");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Digital Editions 4.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:'This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.');

  script_dependencies('adobe_digital_editions_installed.nbin');
  script_require_keys("installed_sw/Adobe Digital Editions", "SMB/Registry/Enumerated");
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('install_func.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Adobe Digital Editions";
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

ver_ui  = NULL;
version = install['version'];
path    = install['path'];
if (!empty_or_null(install['display_version']))  ver_ui  = install['display_version'];

if (version =~ "^4(\.0)?$") audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

# Affected as posted by vendor :
# < 4.0.1
if (version =~ "^([0-3]|4\.0\.0)($|[^0-9])")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  Path              : ' + path;

    if (!empty_or_null(ver_ui))
      report += '\n  Installed version : '+version+' ('+ver_ui+')';
    else
      report += '\n  Installed version : '+version+'';

    report += 
      '\n  Fixed version     : 4.0.1 (4.0.1.101645)' + 
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
