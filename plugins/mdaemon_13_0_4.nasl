#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66634);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_bugtraq_id(58070, 58074, 58077, 58084, 58170, 58171);
  script_osvdb_id(90479, 90505, 90506, 90508, 90509, 91471);
  script_xref(name:"EDB-ID", value:"24534");
  script_xref(name:"EDB-ID", value:"24535");

  script_name(english:"Alt-N MDaemon < 13.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version in MDaemon's banners");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A mail server on the remote Windows host is potentially affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of Alt-N MDaemon that is
earlier than 13.0.4.  It is, therefore, potentially affected by the
following vulnerabilities :

  - An error exists related to the 'Strip X-Headers'
    setting that could allow the application to crash.
    (Issue #10358)

  - An input validation error exists related to displaying
    email body data that could allow cross-site scripting
    attacks. (Issue #10385)

  - A weakness exists related to the generation of session
    IDs that could allow an attacker to hijack user
    sessions. (Issue #10386)

  - An input validation error exists related to the
    'Session' parameter that could allow an attacker to
    obtain encoded credential data. (Issue #10389)

  - An input validation error exists related to 'WebAdmin'
    and account imports that could allow command execution.
    (Issue #10390)

  - An error exists related to the IMAP server that could
    allow plaintext command injection because the server
    does not properly switch from plaintext to ciphertext
    when handling the 'STARTTLS' command. (Issue #10452)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://files.altn.com/mdaemon/release/relnotes_en.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Alt-N MDaemon version 13.0.4 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

fix = "13.0.4";
if (version =~ "^([0-9]\.|1[0-2]\.|13\.0\.[0-3]($|[^0-9]))")
{
  set_kb_item(name: 'www/0/XSS', value: TRUE);
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
