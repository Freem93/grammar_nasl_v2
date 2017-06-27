#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97947);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id("CVE-2017-2640");
  script_bugtraq_id(96775);
  script_osvdb_id(153426);
  script_xref(name:"IAVB", value:"2017-B-0029");

  script_name(english:"Pidgin < 2.12.0 libpurple/util.c purple_markup_unescape_entity() XML Entity Handling RCE");
  script_summary(english:"Performs a version check.");

  script_set_attribute(attribute:"synopsis", value:
"An instant messaging client installed on the remote host is affected
by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Pidgin installed on the remote Windows host is prior to
2.12.0. It is, therefore, affected by a remote code execution
vulnerability in the libpurple library in util.c due to an
out-of-bounds writer error in the purple_markup_unescape_entity()
function that is triggered when handling invalid XML entities
separated by whitespaces. An unauthenticated, remote attacker can
exploit this, via a malicious server, to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://pidgin.im/news/security/?id=109");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pidgin version 2.12.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Pidgin/Path");
version = get_kb_item_or_exit("SMB/Pidgin/Version");
fixed_version = '2.12.0';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (empty_or_null(port)) port = 445;

  report =
    '\n  Path               : ' + path +
    '\n  Installed version  : ' + version +
    '\n  Fixed version      : ' + fixed_version + '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Pidgin", version, path);
