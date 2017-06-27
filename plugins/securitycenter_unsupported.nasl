#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71461);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_name(english:"Tenable SecurityCenter Unsupported Version Detection");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Tenable
SecurityCenter.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable SecurityCenter
on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Tenable SecurityCenter that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_keys("Host/SecurityCenter/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/SecurityCenter/Version");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 4 || (ver[0] == 4 && ver[1] < 6))
{
  register_unsupported_product(product_name:"Tenable SecurityCenter",
                               cpe_base:"tenable:securitycenter", version:version);

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version  : ' + version +
      '\n  Supported versions : 4.6.x / 4.7.x / 4.8.x / 5.0.x\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
