#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72367);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/02/13 16:55:47 $");

  script_name(english:"Microsoft Internet Explorer Version Detection");
  script_summary(english:"Reports Microsoft Internet Explorer version");

  script_set_attribute(attribute:"synopsis", value:"Internet Explorer is installed on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains Internet Explorer, a web browser
created by Microsoft."
  );
  script_set_attribute(attribute:"see_also", value:"http://windows.microsoft.com/en-us/internet-explorer/download-ie");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/IE/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/IE/Version");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Version  : ' + version + 
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
