#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92219);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/07/14 18:29:12 $");

  script_name(english:"Microsoft Visio Unsupported Version Detection");
  script_summary(english:"Checks the Visio version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Microsoft Visio.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Microsoft Visio on the
remote Windows host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/lifecycle/search?sort=PN&alpha=Visio");
  script_set_attribute(attribute:"solution", value:"Upgrade to a supported version of Visio.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("microsoft_visio_installed.nbin");
  script_require_keys("installed_sw/Microsoft Visio");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

installs = get_installs(app_name:"Microsoft Visio", exit_if_not_found:TRUE);

supported_info['2016']['supported_sp']     = 0;
supported_info['2016']['0']['unsupported'] = FALSE;
supported_info['2016']['0']['eos_date']    = "October 14, 2025";

supported_info['2013']['supported_sp']     = 1;
supported_info['2013']['supported_ver']    = "15.0.4569.1504";
supported_info['2013']['1']['unsupported'] = FALSE;
supported_info['2013']['1']['eos_date']    = "April 11, 2023";
supported_info['2013']['0']['unsupported'] = TRUE;
supported_info['2013']['0']['eos_date']    = "February 18, 2015";

supported_info['2010']['supported_sp']     = 2;
supported_info['2010']['supported_ver']    = "14.0.7011.1000";
supported_info['2010']['2']['unsupported'] = FALSE;
supported_info['2010']['2']['eos_date']    = "October 13, 2020";
supported_info['2010']['1']['unsupported'] = TRUE;
supported_info['2010']['1']['eos_date']    = "October 14, 2014";
supported_info['2010']['0']['unsupported'] = TRUE;
supported_info['2010']['0']['eos_date']    = "July 10, 2012";

supported_info['2007']['supported_sp']     = 3;
supported_info['2007']['supported_ver']    = "12.0.6606.1000";
supported_info['2007']['3']['unsupported'] = FALSE;
supported_info['2007']['3']['eos_date']    = "October 10, 2017";
supported_info['2007']['2']['unsupported'] = TRUE;
supported_info['2007']['2']['eos_date']    = "January 8, 2013";
supported_info['2007']['1']['unsupported'] = TRUE;
supported_info['2007']['1']['eos_date']    = "July 13, 2010";
supported_info['2007']['0']['unsupported'] = TRUE;
supported_info['2007']['0']['eos_date']    = "January 13, 2009";

supported_info['2003']['supported_sp']     = -1;
supported_info['2003']['3']['unsupported'] = TRUE;
supported_info['2003']['3']['eos_date']    = "April 8, 2014";
supported_info['2003']['2']['unsupported'] = TRUE;
supported_info['2003']['2']['eos_date']    = "October 14, 2008";
supported_info['2003']['1']['unsupported'] = TRUE;
supported_info['2003']['1']['eos_date']    = "October 10, 2006";
supported_info['2003']['0']['unsupported'] = TRUE;
supported_info['2003']['0']['eos_date']    = "July 27, 2005";

supported_info['2002']['supported_sp']     = -1;
supported_info['2002']['2']['unsupported'] = TRUE;
supported_info['2002']['2']['eos_date']    = "July 12, 2011";
supported_info['2002']['1']['unsupported'] = TRUE;
supported_info['2002']['1']['eos_date']    = "April 11, 2006";
supported_info['2002']['0']['unsupported'] = TRUE;
supported_info['2002']['0']['eos_date']    = "February 1, 2003";

supported_info['2000']['supported_sp']             = -1;
supported_info['2000'][UNKNOWN_VER]['unsupported'] = TRUE;
supported_info['2000'][UNKNOWN_VER]['eos_date']    = "December 31, 2004";

supported_info['v5.0']['supported_sp']             = -1;
supported_info['v5.0'][UNKNOWN_VER]['unsupported'] = TRUE;
supported_info['v5.0'][UNKNOWN_VER]['eos_date']    = "April 30, 2003";

supported_info['v4.5']['supported_sp']             = -1;
supported_info['v4.5'][UNKNOWN_VER]['unsupported'] = TRUE;
supported_info['v4.5'][UNKNOWN_VER]['eos_date']    = NULL;

supported_info['v4.1']['supported_sp']             = -1;
supported_info['v4.1'][UNKNOWN_VER]['unsupported'] = TRUE;
supported_info['v4.1'][UNKNOWN_VER]['eos_date']    = NULL;

supported_info['v4.0']['supported_sp']             = -1;
supported_info['v4.0'][UNKNOWN_VER]['unsupported'] = TRUE;
supported_info['v4.0'][UNKNOWN_VER]['eos_date']    = "December 31, 2001";

supported_info['v3.0']['supported_sp']             = -1;
supported_info['v3.0'][UNKNOWN_VER]['unsupported'] = TRUE;
supported_info['v3.0'][UNKNOWN_VER]['eos_date']    = NULL;

supported_info['v2.0']['supported_sp']             = -1;
supported_info['v2.0'][UNKNOWN_VER]['unsupported'] = TRUE;
supported_info['v2.0'][UNKNOWN_VER]['eos_date']    = NULL;

info = '';
vuln = 0;

foreach install (installs[1])
{
  path    = install['path'];
  product = install['Product'];
  sp      = install['Service Pack'];
  version = install['version'];

  if ( supported_info[product][sp]['unsupported'] == TRUE )
  {
    if (sp != UNKNOWN_VER)
      verbose_version = version + " (" + product + " SP" + sp + ")";
    else
      verbose_version = version + " (" + product + ")";

    if ( supported_info[product]['supported_sp'] >= 0 )
      supported_version = supported_info[product]['supported_ver'] + " (" + product + " SP" + supported_info[product]['supported_sp'] + ")";
    else
      supported_version = "This version is no longer supported.";

    register_unsupported_product(product_name:"Microsoft Visio", version:version,
                                 cpe_base:"microsoft:visio");

    info +=   '\n  Path                       : ' + path +
              '\n  Installed version          : ' + verbose_version +
              '\n  Minimum supported version  : ' + supported_version;
    if (!isnull(supported_info[product][sp]['eos_date']))
      info += '\n  Installed version EOS date : ' + supported_info[product][sp]['eos_date'] + '\n';
    vuln++;
  }
}

if (vuln)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (vuln > 1) s = 's were';
  else s = ' was';

  report =
    '\n' + 'The following unsupported Microsoft Visio installation' + s + ' detected on' +
    '\n' + 'the remote host :' +
    '\n' +
    '\n' + info + '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_NOT_INST, "An unsupported version of Microsoft Visio");
