#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58134);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_name(english:"Microsoft Silverlight Unsupported Version Detection (Windows)");
  script_summary(english:"Checks version of Microsoft Silverlight");

  script_set_attribute(attribute:"synopsis", value:"The remote host has an unsupported version of Microsoft Silverlight.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Microsoft Silverlight on
the Windows host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/gp/lifean45");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Silverlight that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("silverlight_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Silverlight/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


kb_base = "SMB/Silverlight";
path = get_kb_item_or_exit(kb_base+"/Path");
version = get_kb_item_or_exit(kb_base+"/Version");

eos_dates = make_array(
  '4', 'January 8, 2013',
  '3', 'April 12, 2011',
  '2', 'October 12, 2010',
  '1', 'October 12, 2010'
);
supported_versions = '5.x';


ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
version_highlevel = ver[0];

foreach v (keys(eos_dates))
{
  if (v == version_highlevel)
  {
    register_unsupported_product(product_name:"Microsoft Silverlight",
                                 cpe_base:"microsoft:silverlight", version:version);

    if (report_verbosity > 0)
    {
      report =
        '\n  Path               : ' + path +
        '\n  Installed version  : ' + version +
        '\n  Supported versions : ' + supported_versions + '\n';
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
    exit(0);
  }
}
exit(0, 'The Microsoft Silverlight '+version_highlevel+'.x install is currently supported.');

