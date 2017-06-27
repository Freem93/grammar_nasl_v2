#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19252);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_bugtraq_id(14315, 14317);
  script_osvdb_id(18069, 18070);
  script_xref(name:"Secunia", value:"16097");

  script_name(english:"MDaemon IMAP Server Multiple AUTHENTICATE Commands Remote Overflow");
  script_summary(english:"Checks the remote version of MDaemon");

  script_set_attribute(attribute:"synopsis", value:"The remote IMAP server has multiple buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of MDaemon has multiple
buffer overflow vulnerabilities.  A remote attacker could exploit these
issues to crash the service, or possibly execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Jul/422");
  script_set_attribute(attribute:"solution", value:"Upgrade to MDaemon 8.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

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

fix = "8.0.4";
if (version =~ "^([0-7]\.|8\.0\.[0-3]($|[^0-9]))")
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
