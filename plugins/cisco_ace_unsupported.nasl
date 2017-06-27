#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76126);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_name(english:"Cisco Unsupported ACE Module Detection");
  script_summary(english:"Checks ACE Module version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device has an unsupported module installed.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Cisco Application Control Engine (ACE)
module installed on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # http://www.cisco.com/c/en/us/products/collateral/interfaces-modules/services-modules/end_of_life_c51-674429.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab646a3d");
  # http://www.cisco.com/c/en/us/products/collateral/interfaces-modules/services-modules/end_of_life_c51-674428.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?df7768cd");
  script_set_attribute(attribute:"solution", value:"Upgrade to a supported module.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_control_engine_software");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ace_version.nasl");
  script_require_keys("Host/Cisco/ACE/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("url_func.inc");
include("misc_func.inc");

version = get_kb_item("Host/Cisco/ACE/Version");
if (isnull(version)) audit(AUDIT_NOT_INST, 'Cisco ACE');

if (version =~ "^A[12]\(")
{
  enc_ver = urlencode(
    str        : tolower(version),
    unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'-]"
  );
  register_unsupported_product(product_name:"Cisco Application Control Engine",
                               version:enc_ver, cpe_base:"cisco:application_control_engine_software");

  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ACE", version);
