#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87954);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_cve_id("CVE-2015-6409");
  script_osvdb_id(132275);
  script_xref(name:"CISCO-SA", value: "cisco-sa-19990111-ios-syslog");
  script_xref(name:"IAVB", value:"2016-B-0009");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw87419");

  script_name(english:"Cisco Jabber for Windows 8.x / 9.x / 10.x / 11.0.x / 11.1.x XMPP Connection MitM STARTTLS Downgrade (cisco-sa-20151224-jab)");
  script_summary(english:"Checks the version of Cisco Jabber for Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Cisco Jabber for Windows installed on the remote host
is affected by a man-in-the-middle STARTTLS downgrade vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Jabber for Windows installed on the remote host
is 8.x, 9.x, 10.x, 11.0.x, or 11.1.x prior to 11.5. It is, therefore,
affected by man-in-the-middle STARTTLS downgrade vulnerability due to
improper checks to ensure the Extensible Messaging and Presence
Protocol (XMPP) connection is established with Transport Layer
Security (TLS). A man-in-the-middle attacker can exploit this to avoid
TLS negotiation, resulting in the client establishing a cleartext XMPP
connection.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151224-jab
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0655aaae");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuw87419");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Jabber for Windows version 11.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:jabber");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

fixed_version = "11.5(0)";

# Affected versions: 8.x, 9.x, 10.x, 11.0.x, 11.1.x
if (version =~ "^(8|9|10)\.[0-9]+" || version =~ "^11\.(0|1)\.[0-9]+")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + report_version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, report_version, path);
