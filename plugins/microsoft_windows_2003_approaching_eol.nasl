#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/02/11.

include("compat.inc");

if (description)
{
  script_id(80120);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/02/11 21:00:44 $");

  script_name(english:"Microsoft Windows 2003 Approaching End Of Life (deprecated)");
  script_summary(english:"Checks for Windows 2003.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as Windows 2003 is now end-of-life
(EOL).");
  # http://support2.microsoft.com/lifecycle/search/default.aspx?sort=PN&alpha=Microsoft+Windows+Server+2003&Filter=FilterNO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7eae3f0b");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");

  exit(0);
}

exit(0, 'This plugin has been deprecated as Windows 2003 is now end-of-life (EOL).');

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

name    = get_kb_item_or_exit("SMB/ProductName");
version = get_kb_item_or_exit('SMB/WindowsVersion');

# 14 JUN 2015 unixtime
eol_ts = 1436832000;
now    = unixtime();

if (now > eol_ts)
  days_remaining = 'Zero. The product is no longer supported.';
else
  days_remaining = (eol_ts - now) / 60 / 60 / 24;
if (
  version == "5.2"
  &&
  "windows" >< tolower(name)
  &&
  "2003" >< name
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 1)
  {
    report =
      '\n' +
      '\n  Product          : ' + name +
      '\n  End-of-life date : 2015/07/14' +
      '\n  Days remaining   : ' + days_remaining +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_OS_SP_NOT_VULN);
