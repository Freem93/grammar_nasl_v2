#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11570);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id("CVE-2002-1539");
  script_bugtraq_id(6053);
  script_osvdb_id(12047);

  script_name(english:"MDaemon POP Server Multiple Command Remote Overflow DoS");
  script_summary(english:"Determines the version number of the remote POP server");

 script_set_attribute(attribute:"synopsis", value:"The remote POP server has a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote POP server has a denial of service
vulnerability.  Input to the DELE and UIDL commands are not properly
handled.  A remote, authenticated attacker could exploit this to crash
the POP service.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Apr/357");
  script_set_attribute(attribute:"solution", value:"Upgrade to MDaemon 6.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

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

fix = "6.5.0";
if (version =~ "^([0-5]\.|6\.[0-4]($|[^0-9]))")
{
  if (report_verbosity > 0)
  {
    report =
    '\n' +
    '\n  Source            : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "MDaemon", port, version);
