#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58768);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/04/17 20:05:15 $");

  script_name(english:"SSL Resume With Different Cipher Issue");
  script_summary(english:"Tries to resume a session with a different cipher.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host allows resuming SSL sessions with a different cipher
than the one originally negotiated.");
  script_set_attribute(attribute:"description", value:
"The SSL implementation on the remote host has been shown to allow a
cipher other than the one originally negotiated when resuming a
session. An attacker that sees (e.g. by sniffing) the start of an SSL
connection may be able to manipulate session cache to cause subsequent
resumptions of that session to use a cipher chosen by the attacker.");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("ssl_resume.nasl");
  script_require_keys("SSL/Resume/Different");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

# Get the information for each resume, forking as necessary.
port = get_kb_item_or_exit("SSL/Resume/Different");
encaps = get_kb_list_or_exit("SSL/Resume/Different/" + port);
encaps = make_list(encaps);

# If the user doesn't want the details, let's stop right here.
if (report_verbosity == 0)
{
  security_note(port);
  exit(0);
}

report = "";
foreach encap (sort(encaps))
{
  session_id = get_kb_item("SSL/Resume/Different/" + port + "/" + encap + "/Session_ID");
  old_cipher = get_kb_item("SSL/Resume/Different/" + port + "/" + encap + "/Initial");
  new_cipher = get_kb_item("SSL/Resume/Different/" + port + "/" + encap + "/Resumed");

  if (encap == ENCAPS_SSLv3)
    version = "SSLv3";
  else if (encap == ENCAPS_TLSv1)
    version = "TLSv1";
  else
    version = "Unknown";

  report +=
    '\nThe server allowed the following session over ' + version + ' to be resumed as follows :' +
    '\n' +
    '\n  Session ID     : ' + session_id +
    '\n  Initial Cipher : ' + old_cipher + " (0x" + hexstr(ciphers[old_cipher]) + ")" +
    '\n  Resumed Cipher : ' + new_cipher + " (0x" + hexstr(ciphers[new_cipher]) + ")" +
    '\n';
}

security_note(port:port, extra:report);
