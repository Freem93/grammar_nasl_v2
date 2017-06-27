#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72728);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2014-0666");
  script_bugtraq_id(64965);
  script_osvdb_id(102122);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug48056");

  script_name(english:"Cisco Jabber for Windows 9.x < 9.2(2) 'Send Screen Capture' File Write");
  script_summary(english:"Checks version of Cisco Jabber for Windows");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Cisco Jabber for Windows on the remote host is affected
by an arbitrary file write vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Cisco Jabber for Windows installed on the remote host is
9.x prior to 9.2(2).  It is, therefore, affected by an input validation
error related to the 'Send Screen Capture' functionality that could
allow a remote attacker to traverse directories, write arbitrary files
and possibly execute arbitrary code."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-0666
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ffd6b52");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=32451");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Jabber for Windows 9.2(2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:jabber");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:'This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.');

  script_dependencies('cisco_jabber_client_installed.nbin');
  script_require_keys('SMB/Cisco Jabber for Windows/Installed');
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

appname = "Cisco Jabber for Windows";
get_kb_item_or_exit("SMB/" + appname + "/Installed");

kb_installs = get_kb_list_or_exit("SMB/" + appname + "/*/Version");

# If only one install, don't bother branching
if (max_index(keys(kb_installs)) == 1)
{
  item = keys(kb_installs);
  kb_entry = item[0];
}
else
  kb_entry = branch(keys(kb_installs));

version = get_kb_item_or_exit(kb_entry);
kb_base = kb_entry - "/Version";
path = get_kb_item_or_exit(kb_base + "/Path");

ver_ui = get_kb_item(kb_base + "/Ver_UI");

if (ver_ui) report_version = ver_ui + ' (' + version + ')';
else report_version = version;

if (ver_compare(ver:version, fix:"9.2.2", strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + report_version +
      '\n  Fixed version     : 9.2(2)' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, report_version, path);
