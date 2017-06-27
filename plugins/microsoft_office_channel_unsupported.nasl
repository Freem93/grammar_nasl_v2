#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97085);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/02/09 16:33:58 $");

  script_name(english:"Microsoft Office 365 Unsupported Channel Version Detection");
  script_summary(english:"Checks the Microsoft Office Channel version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported Channel version of Microsoft
Office 365.");
  script_set_attribute(attribute:"description", value:
"According to its Channel version, the installation of Microsoft Office
365 on the remote Windows host is no longer supported.

Once a new version of Current Channel or First Release for Deferred
Channel is released, the previous version is no longer supported. Only
the two latest versions of the Deferred Channel are supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/mt592918.aspx");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a Channel version of Microsoft Office 365 that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Office/365");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_hotfixes.inc");

#get_kb_item_or_exit("SMB/Office/365");

app     = "Microsoft Office";
errors  = make_list();
kb_list = make_nested_array();
report  = NULL;

version_mappings = make_array(
  "16.0", "2016"
);

# Current supported versions are added to office_installed.nasl

# Check for Office 365 (Click to Run suite)
foreach ver (keys(version_mappings))
{
  office_suite_supported_vers_kb = "SMB/Office/" + ver + "/SupportedVersions";
  office_suite_supported_vers = get_kb_item(office_suite_supported_vers_kb);
  if (!isnull(office_suite_supported_vers))
  {
    kb_list[office_suite_supported_vers_kb] = office_suite_supported_vers;
  }
}

# If OFfice 365 was not found, check for individual products
if (empty_or_null(kb_list))
{
  kb_list = get_kb_list("SMB/Office/*/SupportedVersions");
  if (empty_or_null(kb_list))
    audit(AUDIT_HOST_NOT, "affected because no Microsoft Office 365 clients were detected");
}

foreach kb (keys(kb_list))
{
  product = 'Microsoft ';
  office_ver = NULL;

  kb_parts = split(kb, sep:"/", keep:FALSE);

  # Individual Office products (Word, Excel, etc.)
  if (max_index(kb_parts) == 5)
  {
    product += kb_parts[2];
    office_ver = kb_parts[3];
  }
  # Suite (Office 2016)
  else if (max_index(kb_parts) == 4)
  {
    product += 'Office';
    office_ver = kb_parts[2];
  }
  else
  {
    errors = make_list(errors, "Unexpected KB item '" + kb + "'." );
    continue;
  }

  supported_versions = kb_list[kb]; #
  kb_base = kb - "SupportedVersions";

  channel = get_kb_item(kb_base + "Channel"); # Current / First Release for Deferred / Deferred 
  if (isnull(channel))
  {
    errors = make_list(errors, "The '" + kb_base + "Channel' KB item is not set.");
    continue;
  }

  channel_version = get_kb_item(kb_base + "ChannelVersion");
  if (isnull(channel_version))
  {
    errors = make_list(errors, "The '" + kb_base + "ChannelVersion' KB item is not set.");
    continue;
  }
  
  supported_versions = get_kb_item(kb_base + "SupportedVersions");
  if (isnull(supported_versions))
  {
    errors = make_list(errors, "The '" + kb_base + "SupportedVersions' KB item is not set.");
    continue;
  }

  product_version = version_mappings[office_ver];
  if (isnull(product_version))
  {
    errors = make_list(errors, "The product version was not found for '" + office_ver  + "'.");
    continue;
  }

  # Determine lowest supported version which will be used to compare against the installed version
  supported_versions_list = sort(split(supported_versions, sep:" / ", keep:FALSE));
  lowest_supported_version = supported_versions_list[0];

  if (channel_version >= lowest_supported_version) continue;

  supported_version_str = "Supported version";
  if (max_index(supported_versions_list) > 1) supported_version_str += "s";
  
  items = make_array();
  items["Installed product"]   = product + ' ' + product_version;
  items["Channel"]             = channel;
  items["Channel version"]     = channel_version;
  items[supported_version_str] = supported_versions;

  order = make_list("Installed product", "Channel", "Channel version", supported_version_str);
  report = report_items_str(report_items:items, ordered_fields:order);

  cpe_base = str_replace(string:tolower(product), find:" ", replace:":");
  version = product_version + " " + channel  + " Channel " + channel_version;

  register_unsupported_product(product_name:product, cpe_base:cpe_base, version:version);

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}

if (isnull(report))
{
  if (max_index(errors) == 1)
    exit(1, 'The following error has occurred :\n' + errors[0]);
  else if (max_index(errors) > 1)
    exit(1, 'The following errors have occurred :\n' + join(errors, sep:'\n'));
  else
    audit(AUDIT_HOST_NOT, "affected because no unsupported versions of Office 365 were detected");
}

