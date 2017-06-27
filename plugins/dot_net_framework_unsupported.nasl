#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72704);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/05/26 16:03:22 $");

  script_name(english:"Microsoft .NET Framework Unsupported");
  script_summary(english:"Checks the version of .NET Framework.");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported software framework is installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, there is at least one
version of Microsoft .NET Framework installed on the remote Windows
host that is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of the Microsoft .NET Framework that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  # https://support.microsoft.com/en-us/lifecycle/search/?sort=pn&alpha=.net%20framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53ee34d3");
  # https://support.microsoft.com/en-us/help/2696944/clarification-on-the-support-life-cycle-for-the-.net-framework-3.5,-the-.net-framework-3.0,-and-the-.net-framework-2.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3265739");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("microsoft_net_framework_installed.nasl");
  script_require_keys("installed_sw/Microsoft .NET Framework");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Microsoft .NET Framework';
get_install_count(app_name:app, exit_if_zero:TRUE);

installs = get_installs(app_name:app);

# We need these for .NET Framework 1.1 on Server 2003 32-bit
winver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
arch = get_kb_item_or_exit('SMB/ARCH', exit_code:1);

net_fw_eol["1.0.3705"]  = "July 14, 2009";
net_fw_eol["1.1.4322"]  = "October 8, 2013";
#net_fw_eol["2.0.50727"] = "April 12, 2016";
net_fw_eol["3.0"]       = "July 13, 2011";
# Support for .NET Framework 4, 4.5, and 4.5.1 will end on January 12, 2016.
net_fw_eol["4"]         =  "January 12, 2016";
net_fw_eol["4.5"]       = "January 12, 2016";
net_fw_eol["4.5.1"]     = "January 12, 2016";

info = '';
net35 = FALSE;
# Check for .NET Framework 3.5
foreach install (installs[1])
{
  ver = install["version"];
  if (ver == '3.5')
  {
    net35 = TRUE;
    break;
  }
}

count = 0;
foreach install (installs[1])
{
  ver = install["version"];
  if (!isnull(net_fw_eol[ver]))
  {
    # Skip .NET Framework 1.1 on Server 2003 32-bit
    if (ver == '1.1.4322' && (winver == '5.2' && arch == 'x86'))
      continue;
    # Skip .NET Framework 3.0 if it is installed as part of 3.5
    if (ver == '3.0' && net35)
      continue;

    register_unsupported_product(product_name:"Microsof .NET Framework",
                                 version:ver, cpe_base:"microsoft:.net_framework");

    count++;
    info +=
      '\n  Installed version  : Microsoft .NET Framework v' + ver +
      '\n  EOL date           : ' + net_fw_eol[ver] +
      '\n  EOL URL            : http://support.microsoft.com/lifecycle/search/?sort=pn&alpha=.net+framework' +
      '\n  Supported versions : 3.5 / 4.5.2 / 4.6 / 4.6.1 / 4.6.2 / 4.7\n';
  }
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (count > 1)
      s = 's are';
    else
      s = ' is';

    report +=
      '\n' + 'The following Microsoft .NET Framework version' + s + ' no longer' +
      '\n' + 'supported :' +
      '\n' +
      '\n' + info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
