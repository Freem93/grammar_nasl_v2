#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66722);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/16 14:02:52 $");

  script_cve_id("CVE-2013-0522");
  script_bugtraq_id(59809);
  script_osvdb_id(93184);

  script_name(english:"IBM Notes Single Sign On Password Disclosure");
  script_summary(english:"Checks if Single Sign On is installed and used");

  script_set_attribute(attribute:"synopsis", value:
"The version of IBM Notes installed on the remote Windows host is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Notes installed on the remote Windows host uses the
built-in Single Sign On feature for authentication.  Single Sign On is
affected by a vulnerability wherein malicious code planted on a user's
workstation can be used to reveal the password of an authenticated
user.");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_for_safer_ibm_notes_single_sign_on_with_windows_use_notes_shared_login_or_notes_federated_login_cve_2013_05221?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e2509e1");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21634508");
  script_set_attribute(attribute:"solution", value:"Disable Notes Client Single Sign On.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("lotus_notes_installed.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Lotus_Notes/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

appname = "IBM Lotus Notes";
kb_base = "SMB/Lotus_Notes/";

port = get_kb_item_or_exit('SMB/transport');
version = get_kb_item_or_exit(kb_base + 'Version');
path = get_kb_item_or_exit(kb_base + 'Path');
ver_ui = get_kb_item_or_exit(kb_base + 'Version_UI');

ver = split(version, sep:'.');
if (version =~ '^(8\\.(0\\.|5\\.[0-3])|9\\.0)')
{
  if (int(ver[0]) >= 9)
  {
    status = get_kb_item_or_exit('SMB/svc/IBM Notes Single Logon');
    if (status != SERVICE_ACTIVE)
      exit(0, 'The IBM Notes Single Logon service is installed but not active.');
  }
  else
  {
    status = get_kb_item_or_exit('SMB/svc/Lotus Notes Single Logon');
    if (status != SERVICE_ACTIVE)
      exit(0, 'The Lotus Notes Single Logon service is installed but not active.');
  }

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver_ui + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_ui, path);
