#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45627);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_bugtraq_id(39657);
  script_osvdb_id(64038, 64039);

  script_name(english:"Alt-N MDaemon < 11.0.1 Multiple Remote DoS");
  script_summary(english:"Checks version in MDaemon's banners");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a program that is prone to multiple
remote denial of service attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of Alt-N MDaemon that is
earlier than 11.0.1.  As such, it is prone to multiple remote denial of
service attacks.  An attacker may exploit these issues to deny the
application's services to legitimate users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://files.altn.com/mdaemon/release/relnotes_en.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Alt-N MDaemon version 11.0.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

fix = "11.0.1.0";
if (version =~ "^([0-9]\.|10\.|11\.0\.0($|[^0-9]))")
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
