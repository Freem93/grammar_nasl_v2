#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65642);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_name(english:"BlackBerry Enterprise Server Unsupported Version");
  script_summary(english:"Checks version of BlackBerry Enterprise Server");

  script_set_attribute(attribute:"synopsis", value:"The remote host has unsupported software installed.");
  script_set_attribute(attribute:"description", value:
"The remote host has an unsupported version of BlackBerry Enterprise
Server installed.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # http://ca.blackberry.com/support/business/software-support-life-cycle.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?165e16b9");
  script_set_attribute(attribute:"solution", value:"Upgrade to a supported version of BlackBerry Enterprise Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rim:blackberry_enterprise_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl", "lotus_domino_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

port = kb_smb_transport();

global_var prod, version;

# returns text string of supported versions if unsupported
function is_unsupported()
{
  local_var matches, mr;

  # Unsupported Versions:
  #   BES for Exchange:
  #     4.1 SP4, 4.1 SP5, 4.1 SP6, 4.1 SP7, 5.0, and 5.0 SP1
  #   BES for Lotus Domino:
  #     4.1 SP4, 4.1 SP5, 4.1 SP6, 4.1 SP7, 5.0, and 5.0 SP1
  #   BES for Novell GroupWise:
  #     4.1 SP4, 4.1 SP6, 4.1 SP7
  mr = "(?: MR ([0-9]+))?( |$)";

  # Ignore anything that isn't BES.
  if ("Enterprise Server" >!< prod) return FALSE;

  if ("Microsoft Exchange" >< prod || "IBM Lotus Domino" >< prod)
  {
    if(version =~ "^4\.")
    {
      # 4.1 SP4 though 4.1 SP7
      matches = eregmatch(string:version, pattern:"^4\.1\.([4-7])" + mr);
      if (isnull(matches)) return FALSE;
      return '5.0.2 and above';
    }
    else
    {
      # 5.0 SP0 through 5.0 SP1
      matches = eregmatch(string:version, pattern:"^5\.0\.([01])" + mr);
      if (isnull(matches)) return FALSE;
      return '5.0.2 and above';
    }
  }

  if ("Novell GroupWise" >< prod)
  {
    # 4.1 SP4, 4.1 SP6, 4.1 SP7
    matches = eregmatch(string:version, pattern:"^4\.1\.([467])" + mr);
    if (isnull(matches)) return FALSE;
    return '5.0.1 and above';
  }

  exit(0, prod + " is not on a recognized platform.");
}

prod = get_kb_item_or_exit("BlackBerry_ES/Product");
version = get_kb_item_or_exit("BlackBerry_ES/Version");

base = get_kb_item_or_exit("BlackBerry_ES/Path");
if ("IBM Lotus Domino" >< prod)
  base = get_kb_item_or_exit("SMB/Domino/Path");

supported_version = is_unsupported();

if (supported_version)
{
  register_unsupported_product(product_name:"Blackberry Enterprise Server", version:version, cpe_base:"rim:blackberry_enterprise_server");

  if (report_verbosity > 0)
  {
    report =
     '\n  Product            : ' + prod +
     '\n  Path               : ' + base +
     '\n  Installed version  : ' + version +
     '\n  Supported versions : ' + supported_version +
     '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, prod, version);
