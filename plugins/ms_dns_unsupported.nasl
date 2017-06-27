#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74496);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_name(english:"Unsupported Microsoft DNS Server Detection");
  script_summary(english:"Checks version of DNS server");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of Microsoft DNS
server.");
  script_set_attribute(attribute:"description", value:
"Nessus detected a version of Microsoft DNS server listening on the
remote host that belongs to an unsupported version of Windows.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/lifecycle/?c2=1163");
  script_set_attribute(attribute:"solution", value:"Upgrade to a supported version of Microsoft Windows.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:dns_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("ms_dns_version.nasl");
  script_require_keys("ms_dns/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("ms_dns/version");
port = 53;

fix = NULL;
supported_os = NULL;

# Server 2k and below are no longer supported by Microsoft
if (ver_compare(ver:version, fix:"5.2", strict:FALSE) == -1)
{
  fix = "None available (on unsupported operating system)";
}
# Server 2003
# 5.2.3790.3959 is first version packaged with SP2
else if (
  version =~ "^5\.2\." &&
  ver_compare(ver:version, fix:"5.2.3790.3959", strict:FALSE) == -1
)
{
  fix = "5.2.3790.3959 or higher";
  supported_os = "Server 2003 Service Pack 2";
}
# Server 2008
# 6.0.6002 is SP2
else if (
  version =~ "^6\.0\." &&
  ver_compare(ver:version, fix:"6.0.6002", strict:FALSE) == -1
)
{
  fix = "6.0.6002 or higher";
  supported_os = "Server 2008 Service Pack 2";
}
# Server 2008 R2
# 6.1.7601 is SP1
else if (
  version =~ "^6\.1\." &&
  ver_compare(ver:version, fix:"6.1.7601", strict:FALSE) == -1
)
{
  fix = "6.1.7601 or higher";
  supported_os = "Server 2008 R2 Service Pack 1";
}

if (isnull(fix))
  audit(AUDIT_LISTEN_NOT_VULN, "Microsoft DNS", port, version, "UDP");

register_unsupported_product(product_name:"Microsoft DNS Server", is_custom_cpe:TRUE,
                             cpe_base:"microsoft:dns_server", version:version);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version         : ' + version +
    '\n  Minimum supported version : ' + fix;

  if (!isnull(supported_os))
    report += '\n  Recommended upgrade       : ' + supported_os;

  report += '\n';

  security_hole(port:port, proto:"udp", extra:report);
}
else security_hole(port:port, proto:"udp");
