#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50706);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2011/10/24 19:37:28 $");

  script_bugtraq_id(45021, 45022, 45024);

  script_name(english:"Pidgin < 2.7.6 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An instant messaging client installed on the remote Windows host is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Pidgin installed on the remote host is earlier than
2.7.6.  Such versions are potentially affected by multiple
vulnerabilities:

  - An error in the application media code allows a 
    user-after-free race condition when an error has been
    reported by GStreamer. This can result in an 
    application crash. (12806)

  - An error in the Google Relay procedures which attempt to
    free resources two times and can lead to denial of 
    service conditions.

  - An error in the MSN handling portion of the application
    attempts to use resources after freeing them leading to
    application crashes and may allow arbitrary code
    execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://developer.pidgin.im/wiki/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://developer.pidgin.im/ticket/12806"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Pidgin 2.7.6 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/11/21");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/24");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Pidgin/Version");
fixed_version = '2.7.6';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  path = get_kb_item_or_exit("SMB/Pidgin/Path");
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report =
      '\n  Install path       : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "Pidgin " + version + " is installed and hence not affected.");
