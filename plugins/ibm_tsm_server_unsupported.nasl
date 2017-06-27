#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81494);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:08:40 $");

  script_name(english:"Tivoli Storage Manager Server Unsupported Product");
  script_summary(english:"Checks the version of Tivoli Storage Manager server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported product that may be affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the IBM Tivoli Storage Manager server
running on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor under a standard support contract. As a
result, it is likely to contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/software/sysmgmt/products/support/lifecycle/");
  script_set_attribute(attribute:"solution", value:"Upgrade to a supported version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ibm_tsm_detect.nasl");
  script_require_keys("installed_sw/IBM Tivoli Storage Manager");
  script_require_ports("Services/tsm-agent");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

port = get_service(svc:"tsm-agent",exit_on_fail:TRUE);
prod = "IBM Tivoli Storage Manager";

install = get_single_install(app_name:prod, port:port, exit_if_unknown_ver:TRUE);

version = install["version"];

supported_version = '6.3';

if(ver_compare(ver:version, fix:supported_version, strict:FALSE) == -1)
{
  register_unsupported_product(product_name:prod, version:version,
                               cpe_base:"ibm:tivoli_storage_manager");
  if(report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + supported_version + '.x or higher' +
      '\n';
    security_hole(port:port,extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port);
