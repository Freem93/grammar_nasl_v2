#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56468);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/08/21 14:54:56 $");

  script_name(english:"Time of Last System Startup");
  script_summary(english:"Reports time of last reboot");

  script_set_attribute(attribute:"synopsis", value:"The system has been started.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to determine when the
host was last started.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("huawei_vrp_version.nbin", "palo_alto_version.nbin", "ssh_get_info.nasl", "wmi_last_reboot.nbin");
  script_require_keys("Host/last_reboot");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


last = get_kb_item_or_exit("Host/last_reboot");

if (report_verbosity > 0)
{
  if (
    (
      "wtmp begins" >< last &&
      "reboot " >!< last &&
      !ereg(pattern:"^System Up Time *: *(hr|min|sec)", string:last)
    ) ||
    (
      "No such" >< last ||
      !ereg(pattern:"^.*\d+.*", string:last)
    )
  )
  {
    report = '\n  The host has not yet been rebooted.\n';
  }
  else
  {
    report = '\n';
    foreach line (split(last, keep:TRUE))
    {
      report += '  ' + line;
    }
  }

  security_note(port:0, extra:report);
}
else security_note(0);
