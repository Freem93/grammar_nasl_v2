#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59732);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_osvdb_id(81805);
  script_xref(name:"EDB-ID", value:"18817");

  script_name(english:"MikroTik Winbox < 5.17 File Download DoS");
  script_summary(english:"Checks the version of MikroTik Winbox");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
MikroTik Winbox hosted on the remote web server is affected by a
denial of service vulnerability. An unauthenticated, remote attacker
may make multiple requests to download a large file, resulting in the
service becoming unresponsive. Successful attacks can disconnect all
Winbox clients, and make the service unresponsive for several minutes.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MikroTik RouterOS 5.17 or later, disable the Winbox
service, or restrict the hosts that can access it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://www.mikrotik.com/download/CHANGELOG_5");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16334b87");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:mikrotik:winbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mikrotik_winbox_detect.nasl");
  script_require_ports("Services/mikrotik_winbox");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

app = "MikroTik Winbox";

# Try to get the version number of Winbox.
port = get_service(svc:"mikrotik_winbox", exit_on_fail:TRUE);
ver = get_kb_item_or_exit("MikroTik/Winbox/" + port + "/Version");
if (ver == "unknown") exit(1, "The version of " + app + " on the remote host is not known.");
if (ver !~ "^[\d.]+$") exit(1, "The version of " + app + " - " + ver + " - is non-numeric and, therefore, cannot be used to make a determination.");

# Versions earlier than 5.17 are vulnerable.
fix = "5.17";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  exit(0, app + " version " + ver + " on port " + port + " on the remote host is not affected.");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_warning(port:port, extra:report);
