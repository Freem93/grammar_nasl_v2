#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65675);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/25 15:30:54 $");

  script_cve_id("CVE-2013-1085");
  script_bugtraq_id(58529);
  script_osvdb_id(91477);

  script_name(english:"Novell Messenger Client Import Command Remote Code Execution");
  script_summary(english:"Checks version of Novell Messenger Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by an arbitrary
code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Novell Messenger (formerly GroupWise Messenger
Client) is affected by a buffer overflow vulnerability that can be
triggered by providing a large filename parameter to the import command
via the 'nim://' protocol.  By tricking a user into opening a specially
crafted page or file, it may be possible to execute arbitrary code."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-036/");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7011935");
  script_set_attribute(attribute:"solution", value:"Upgrade to Novell Messenger 2.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:messenger");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_messenger");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("novell_messenger_client_installed.nasl");
  script_require_keys("SMB/Novell_Messenger_Client/Version");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include("misc_func.inc");
include('smb_func.inc');

app = 'Novell Messenger Client';
kb_base = "SMB/Novell_Messenger_Client/";
port = kb_smb_transport();

version = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

fix = "2.2.2.0";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
