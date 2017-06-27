#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63683);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_name(english:"VMware View Server Unsupported Version Detection");
  script_summary(english:"Checks if a VMware View Server version is unsupported");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of a virtual desktop
solution.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of VMware View Server,
formerly known as VMware Virtual Desktop Infrastructure, on the remote
host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/files/pdf/support/Product-Lifecycle-Matrix.pdf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of VMware View Server that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:view");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("vmware_view_server_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/ViewServer/Installed");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("VMware/ViewServer/Path");
version = get_kb_item_or_exit("VMware/ViewServer/Version");

# nb: these dates are for the end of "Extended Support"; in "Technical
#     Guidance", the life cycle policy document specifically says
#     there will be no security patches.
eos_dates = make_array(
#  "^5\.", 'September 14, 2016',
  "^4\.", 'November 16, 2014',
  "^3\.", 'May 11, 2011',
  "^2\.", 'June 2, 2010'
);
supported_versions = '5.x';

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
version_highlevel = strcat(ver[0], ".", ver[1]);

foreach v (keys(eos_dates))
{
  if (version_highlevel =~ v)
  {
    register_unsupported_product(product_name:"VMWare ViewServer",
                                 cpe_base:"vmware:view", version:version);

    if (report_verbosity > 0)
    {
      report +=
        '\n  Path               : ' + path +
        '\n  Installed version  : ' + version +
        '\n  EOL date           : ' + eos_dates[v] +
        '\n  Supported versions : ' + supported_versions +
        '\n';
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
    exit(0);
  }
}
exit(0, "The VMware View Server " + version +" install is currently supported.");
