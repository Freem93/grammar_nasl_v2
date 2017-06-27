#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44942);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(38427);
  script_osvdb_id(62586);
  script_xref(name:"Secunia", value:"38734");

  script_name(english:"XMail < 1.27 Insecure Temporary File Creation");
  script_summary(english:"Checks the SMTP server banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a mail server that creates temporary files
insecurely."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its SMTP service banner, the version of XMail running on
the remote host creates temporary files insecurely. 

A local attacker could exploit this to overwrite arbitrary files by
using symlink attacks, which could lead to privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.xmailserver.org/ChangeLog.html#feb_25__2010_v_1_27"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to XMail 1.27 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value: "2010/02/25");
  script_set_attribute(attribute:"patch_publication_date", value: "2010/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/03/01");
 script_cvs_date("$Date: 2011/03/11 20:59:05 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");


if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

banner = get_smtp_banner(port:port);
if (!banner) exit(1, "Unable to get banner from SMTP server on port "+port+".");
if ("[xmail " >!< tolower(banner)) exit(0, "The SMTP server on port "+port+" does not appear to be from XMail.");
 
match = eregmatch(string:banner, pattern:'\\[xmail ([0-9.]+) ', icase:TRUE);
if (match)
{
  version = match[1];

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    ver[0] < 1 ||
    (ver[0] == 1 && ver[1] < 27)
  )
  {
    if (report_verbosity > 0)
    {
      report = '\n' +
        'XMail version '+ version + ' appears to be running on the remote host based\n' +
        'on the following banner :\n' +
        '\n' +
        '  ' + banner + '\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);

    exit(0);
  }
  else exit(0, "XMail version "+version+" is installed and therefore not affected.");
}
else exit(1, "Failed to extract the XMail version from the SMTP server on port "+port+".");
