#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50350);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/09/05 14:00:45 $");

  script_name(english:"OS Identification Failed");
  script_summary(english:"Reports missing fingerprints in KB");

  script_set_attribute(attribute:"synopsis", value:"It was not possible to determine the remote operating system.");
  script_set_attribute(attribute:"description", value:
"Using a combination of remote probes (TCP/IP, SMB, HTTP, NTP, SNMP,
etc), it was possible to gather one or more fingerprints from the
remote system. Unfortunately, though, Nessus does not currently know
how to use them to identify the overall system.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
  script_family(english:"General");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("Host/OS/Fingerprint/Fail");
  exit(0);
}

kb = get_kb_item("Host/OS/Fingerprint/Fail");
if (isnull(kb)) exit(0, "The host does not have any missing OS fingerprints.");

kb2 = '';
foreach line (split(kb, keep:FALSE))
{
  line = chomp(line);

  # nb: Ignore fingerprints that we can't use.
  if (line == "HTTP:!:Server: Apache") continue;

  if (line == "NTP:!:UNIX") continue;

  if (line == "SMTP:!:220") continue;
  if (ereg(pattern:"^SMTP:\!:220 [^ ]+ E?SMTP$", string:line)) continue;
  if (preg(pattern:"^SMTP:\!:220 [^ ]+ E?SMTP Sendmail [0-9.]+/[0-9.]+; [A-Za-z]{3}, +[0-9]{1,2} [A-Za-z]{3} [0-9]{4} [0-9][0-9]:[0-9][0-9]:[0-9][0-9] [-+][0-9]{4} \([A-Za-z]{3}\)$", string:line)) continue;

  if (ereg(pattern:"^SSH:\!:SSH-[0-9.]+-OpenSSH_[0-9.]+$", string:line)) continue;

  kb2 += line + '\n';
}
if (isnull(kb2)) exit(0, "The host does not have any missing OS fingerprints that appear usable.");

if (max_index(split(kb2)) > 1)
{
  report =
    '\n' + 'If you think these signatures would help us improve OS fingerprinting,' +
    '\n' + 'please send them to :';
}
else
{
  report =
    '\n' + 'If you think this signature would help us improve OS fingerprinting,' +
    '\n' + 'please send it to :';
}

report +=
  '\n' +
  '\n' + '  os-signatures@nessus.org' +
  '\n' +
  '\n' + 'Be sure to include a brief description of the device itself, such as' +
  '\n' + 'the actual operating system or product / model names.' +
  '\n' +
  '\n' + kb2;
security_note(port:0, extra:report);
