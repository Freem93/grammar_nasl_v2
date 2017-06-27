#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66272);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/30 18:25:14 $");

  script_bugtraq_id(58840);
  script_osvdb_id(91982);
  script_xref(name:"EDB-ID", value:"24923");

  script_name(english:"Google Apps Directory Sync < 3.1.6 Weak Stored Credential Local Disclosure");
  script_summary(english:"Checks version number of Google Apps Directory Sync");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a LDAP synchronization tool that is affected
by a weak stored credential local disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Apps Directory Sync installed on the remote host
is earlier than 3.1.6 and is, therefore, affected by a weak stored
credential local disclosure vulnerability.  An issue exists in the way
'PBEwithMD5andDES' Java encryption algorithm is implemented, allowing a
local attacker to decrypt stored credentials.");
  script_set_attribute(attribute:"see_also", value:"http://support.google.com/a/bin/answer.py?hl=en&answer=1263028");
  # http://packetstormsecurity.com/files/121064/Google-Active-Directory-Sync-GADS-Tool-3.1.3-Information-Disclosure.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2043a1cd");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Apps Directory Sync 3.1.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:google:apps_directory_sync");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("google_dir_sync_installed.nasl");
  script_require_keys("SMB/Google_Dir_Sync/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Google Apps Directory Sync";
kb_base = "SMB/Google_Dir_Sync/";

# Check each installation.
get_kb_item_or_exit(kb_base + "Installed");
version = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

fix = "3.1.6";
port = get_kb_item("SMB/transport");

if(ver_compare(ver:version, fix:fix, strict:FALSE) == -1 )
{
  if (report_verbosity > 0)
  {
    report =
            '\n  Path              : ' + path +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : ' + fix +
            '\n';
    security_note(port:port, extra:report);
  } else security_note(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
