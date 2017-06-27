#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14804);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id("CVE-2004-1546");
  script_bugtraq_id(11238);
  script_osvdb_id(10223, 10224);

  script_name(english:"MDaemon < 6.5.2 Multiple Remote Buffer Overflows");
  script_summary(english:"Checks the remote version of Mdaemon");

  script_set_attribute(attribute:"synopsis", value:"The remote SMTP server has multiple buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of MDaemon running on the remote
host has multiple buffer overflow vulnerabilities.  A remote attacker
could exploit these issues to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Sep/821");
  script_set_attribute(attribute:"solution", value:"Upgrade to MDaemon 6.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

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

fix = "6.5.2";
if (version =~ "^([0-5]\.|(6\.[0-4]|6\.5\.[01])($|[^0-9]))")
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
