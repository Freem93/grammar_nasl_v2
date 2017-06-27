#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80198);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/29 16:45:58 $");

  script_name(english:"Juniper Junos Space Unsupported Release");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:
"The network management software on the remote device is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Juniper Junos Space on the remote device is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.juniper.net/support/eol/space.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Junos Space that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Junos_Space/version");

# supported versions : 15.1
# Note: Juniper uses EoE and EoS. EoE refers to
#       end of engineering, meaning that no new
#       patches will be created for these versions.
fix = '15.1R0.0';

if (_junos_space_ver_compare(ver:version, fix:fix) < 0)
{
  register_unsupported_product(product_name:"Junos Space", version:version, cpe_base:"juniper:junos_space");

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version  : ' + version +
      '\n  Supported version  : 15.1' +
      '\n  EOL URL            : http://www.juniper.net/support/eol/space.html' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, 'Junos Space ' + version + ' is not affected.');
