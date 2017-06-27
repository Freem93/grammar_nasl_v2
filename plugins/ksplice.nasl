#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65047);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/06 17:23:57 $");

  script_name(english:"KSplice : Installed Patches");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is using KSplice to maintain the OS kernel."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Ksplice is being used to maintain the remote host's operating system
kernel without requiring reboots."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.ksplice.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"General");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (!get_kb_item("Host/uptrack-uname-a")) audit(AUDIT_NOT_INST, "KSplice");

# if the file /etc/uptrack/disable exists then ksplice/uptrack is disabled
if (get_kb_item("Host/uptrack-disable-file")) exit(0, "Ksplice is installed but is not currently being used.");

report = "";
if (get_kb_item("Host/uptrack-show-installed"))
{
  installed_patches = get_kb_item("Host/uptrack-show-installed");
  installed_patches = ereg_replace(pattern:"\nEffective kernel version.*", replace:"", string:installed_patches);
  report += installed_patches;
}
if (report != "") report += '\n' + '\n';
if (get_kb_item("Host/uptrack-show-available"))
{
  available_patches = get_kb_item("Host/uptrack-show-available");
  available_patches = ereg_replace(pattern:"\nEffective kernel version.*", replace:"", string:available_patches);
  report += available_patches;
}
if (report_verbosity > 0) security_note(port:0, extra:report);
else security_note(0);
