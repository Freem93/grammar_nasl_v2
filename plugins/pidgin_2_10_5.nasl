#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59969);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2012-3374");
  script_bugtraq_id(54322);
  script_osvdb_id(83605);

  script_name(english:"Pidgin < 2.10.5 mxit_show_message Function RX Message Inline Image Parsing Remote Overflow");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An instant messaging client installed on the remote Windows host is
affected by a buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Pidgin installed on the remote host is earlier than
2.10.5.  As such, it is potentially affected by a stack-based buffer
overflow vulnerability. 

An error in the function 'mxit_show_message' in the file
'libpurple/protocols/mxit/markup.c' can allow a stack-based buffer
overflow to occur when parsing a received message containing inline
images.  This can result in application crashes and potentially
arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://hg.pidgin.im/pidgin/main/rev/ded93865ef42");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=64");
  script_set_attribute(attribute:"solution", value:"Upgrade to Pidgin 2.10.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Pidgin/Path");
version = get_kb_item_or_exit("SMB/Pidgin/Version");
fixed_version = '2.10.5';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report =
      '\n  Path               : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Pidgin", version, path);
