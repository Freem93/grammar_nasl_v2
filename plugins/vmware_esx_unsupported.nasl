#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56997);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_name(english:"VMware ESX / ESXi Unsupported Version Detection");
  script_summary(english:"Checks if a VMware ESX / ESXi version is unsupported");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of a virtualization
application.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of VMware ESX or ESXi on
the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/support/policies/lifecycle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/files/pdf/support/Product-Lifecycle-Matrix.pdf");
  script_set_attribute(attribute:"solution", value:"Upgrade to a version of VMware ESX / ESXi that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:esx_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"VMware ESX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

esx_version = get_kb_item_or_exit("Host/VMware/version");

match = eregmatch(pattern:"^(ESXi?) ([0-9].+)", string:esx_version);
if (!match) exit(1, "Failed to parse the ESX/ESXi version ("+esx_version+").");

product = match[1];
version = match[2];

# nb: these dates are for the end of "Extended Support"; in "Technical
#     Guidance", the life cycle policy document specifically says
#     there will be no security patches.
if ("ESXi" >< product)
{
  # ESXi
  eos_dates = make_array(
  #  "^5\.5$"    , 'September 19, 2018',
  #  "^5\.[01]$" , 'August 08, 2016',
    "^4\.[01]$" , 'May 21, 2014',
    "^3\.5$"    , 'May 21, 2013',
    "^3\.0$"    , 'No date available'
  );
  supported_versions = '5.5 / 5.1 / 5.0';
}
else
{
  # ESX
  eos_dates = make_array(
    "^4\.[01]$" , 'May 21, 2014',       # http://kb.vmware.com/kb/2039567
    "^3\.5$"    , 'May 21, 2013',
    "^3\.0$"    , 'December 10, 2011',
    "^2\.5$"    , 'June 15, 2010',
    "^2\.[01]$" , 'No date available',
    "^1\.[015]$", 'No date available'
  );
  supported_versions = NULL;
}

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
version_highlevel = ver[0] + "." + ver[1];

foreach v (keys(eos_dates))
{
  if (version_highlevel =~ v)
  {
    if ("ESXi" >< product) tag_name = "vmware:esxi";
    else tag_name = "vmware:esx_server";

    register_unsupported_product(product_name:product, cpe_class:CPE_CLASS_OS,
                                 cpe_base:tag_name, version:version);
    if (report_verbosity > 0)
    {
      report +=
        '\n  Product            : ' + product +
        '\n  Installed version  : ' + version +
        '\n  EOL date           : ' + eos_dates[v];
      if (!isnull(supported_versions)) report += '\n  Supported versions : ' + supported_versions;
      report += '\n';
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
    exit(0);
  }
}
audit(AUDIT_INST_VER_NOT_VULN, "VMware "+product, version_highlevel);
