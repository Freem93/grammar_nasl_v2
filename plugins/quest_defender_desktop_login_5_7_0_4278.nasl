#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65930);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_bugtraq_id(58543);
  script_osvdb_id(91476);

  script_name(english:"Quest Defender Desktop Login Component Unspecified Vulnerability");
  script_summary(english:"Checks version of Quest Defender Desktop Login Component");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an authentication application that is affected by
an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Quest Defender Desktop Login Component installed on the
remote Windows host is prior to 5.7.0.4278. It is, therefore,
potentially affected by an unspecified security vulnerability
according to Quest knowledge base article SOL104608.");
  script_set_attribute(attribute:"see_also", value:"https://www.quest.com/products/defender/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Quest Defender Desktop Login Component 5.7.0.4278 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:quest:defender");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("quest_defender_desktop_login_installed.nasl");
  script_require_keys("SMB/Quest Defender Desktop Login Component/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Quest Defender Desktop Login Component/Version");
path = get_kb_item_or_exit("SMB/Quest Defender Desktop Login Component/Path");

if (ver_compare(ver:version, fix:'5.7.0.4278') < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.7.0.4278\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Quest Defender Desktop Login Component', version, path);
