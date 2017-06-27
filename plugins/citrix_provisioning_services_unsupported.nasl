#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(59017);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/24 17:01:59 $");

  script_name(english:"Citrix Provisioning Services Unsupported Version Detection");
  script_summary(english:"Checks the version of Citrix Provisioning Services.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application running on the remote host
is unsupported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Citrix Provisioning Services running on the remote host is no longer
supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.citrix.com/support/product-lifecycle/product-matrix.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Citrix Provisioning Services that is
currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:provisioning_services");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("citrix_provisioning_services_detect.nasl");
  script_require_keys("SMB/Citrix/Provisioning_Services/Version", "SMB/Citrix/Provisioning_Services/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

path = get_kb_item_or_exit("SMB/Citrix/Provisioning_Services/Path");
prodversion = get_kb_item_or_exit("SMB/Citrix/Provisioning_Services/Version");

ver = split(prodversion, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 7)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  register_unsupported_product(product_name:"Citrix Provisioning Services",
                               version:prodversion, cpe_base:"citrix:provisioning_services");

  report =
    '\n  Path                 : ' + path +
    '\n  Installed version    : ' + prodversion +
    '\n  Supported version(s) : 7.x\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}
else exit(0, 'The Citrix Provisioning Services '+prodversion+' installation under '+path+' is currently supported.');
