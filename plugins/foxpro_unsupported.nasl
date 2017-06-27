#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92700);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/08/03 15:58:52 $");

  script_name(english:"Microsoft Visual FoxPro Unsupported Version Detection");
  script_summary(english:"Checks the Microsoft Visual FoxPro version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is no longer supported by
the vendor.");
  script_set_attribute(attribute:"description", value:
"Microsoft Visual FoxPro has been discontinued by Microsoft. Therefore,
the installation of Visual FoxPro on the remote Windows host is
unsupported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://msdn.microsoft.com/en-us/vfoxpro/bb308952.aspx");
  # https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=FoxPro&Filter=FilterNO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29ba0a28");
  script_set_attribute(attribute:"solution", value:
"Remove Microsoft Visual FoxPro from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_foxpro");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("foxpro_installed.nasl");
  script_require_keys("installed_sw/Visual FoxPro");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

appname = 'Visual FoxPro';
install = get_single_install(app_name:appname);

# all versions are unsupported
if (!empty_or_null(install))
{
  version = install['version'];
  path = install['path'];
  register_unsupported_product(product_name:"Visual FoxPro", version:version, cpe_base:"microsoft:visual_foxpro");

  report = '\n  Path                : ' + path +
           '\n  Installed version   : ' + version +
           '\n  Solution            : Remove Microsoft Visual FoxPro';

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_NOT_INST, appname);
