#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19310);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_bugtraq_id(14400);
  script_osvdb_id(18348);
  script_xref(name:"Secunia", value:"16173");

  script_name(english:"MDaemon Content Filter Traversal Arbitrary File Write");
  script_summary(english:"Checks for content filter directory traversal vulnerability in MDaemon");

  script_set_attribute(attribute:"synopsis", value:"The remote mail server is prone to directory traversal attacks.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of MDaemon on the remote host is
prone to a directory traversal flaw that can be exploited to overwrite
files outside the application's quarantine directory provided MDaemon's
attachment quarantine feature is enabled.");
  script_set_attribute(attribute:"see_also", value:"http://files.altn.com/MDaemon/Release/RelNotes_en.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to MDaemon version 8.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("mdaemon_detect.nasl");
  script_require_keys("mdaemon/installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item_or_exit("mdaemon/port");

version = get_kb_item_or_exit("mdaemon/"+port+"/version");
source = get_kb_item_or_exit("mdaemon/"+port+"/source");

fix = "8.1.0";
if (version =~ "^([0-7]\.|8\.0($|[^0-9]))")
{
  if (report_verbosity > 0)
  {
    report =
    '\n' +
    '\n  Source            : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
} 
else audit(AUDIT_LISTEN_NOT_VULN, "MDaemon", port, version);
