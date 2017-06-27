#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15823);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id("CVE-2004-2504");
  script_bugtraq_id(11736);
  script_osvdb_id(12158);

  script_name(english:"MDaemon File Creation Local Privilege Escalation");
  script_summary(english:"Checks the remote version of Mdaemon");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is prone to a local privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"It is reported that versions of MDaemon up to and including 7.2.0 are
affected by a local privilege escalation vulnerability. 

An local attacker may increase his privilege and execute code with
SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Nov/1367");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Nov/1392");
  script_set_attribute(attribute:"solution", value:"Upgrade to MDaemon 7.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"SMTP problems");

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

fix = "7.2.1";
if (version =~ "^([0-6]\.|(7\.[01]|7\.2\.0)($|[^0-9]))")
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
