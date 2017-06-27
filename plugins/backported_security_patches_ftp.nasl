#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(39519);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2015/07/07 17:20:51 $");

 script_name(english:"Backported Security Patch Detection (FTP)");
 script_summary(english:"Checks for backported security patches.");

 script_set_attribute(attribute:"synopsis", value:
"Security patches are backported.");
 script_set_attribute(attribute:"description", value:
"Security patches may have been 'backported' to the remote FTP server
without changing its version number. 

Banner-based checks have been disabled to avoid false positives. 

Note that this test is informational only and does not denote any
security problem.");
 script_set_attribute(attribute:"see_also", value: "https://access.redhat.com/security/updates/backporting/?sc_cid=3093");
 script_set_attribute(attribute:"solution", value: "n/a");
 script_set_attribute(attribute:"risk_factor", value: "None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_dependencie("global_settings.nasl", "ftpserver_detect_type_nd_version.nasl", "ssh_get_info.nasl");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");
include("backport.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port: port);
if (strlen(banner) == 0) audit(AUDIT_NO_BANNER, port);

backported = 0;
banner2 = get_backport_banner(banner:banner);
if (banner != banner2)
{
  if (report_verbosity > 0)
  {
    if (get_kb_item("Host/local_checks_enabled"))
      info = "Local checks have been enabled.";
    else
      info = "Give Nessus credentials to perform local checks.";

    info = '\n' + info + '\n';
    security_note(port:port, extra:info);
  }
  else security_note(port);
}
else exit(0, "The FTP server listening on port "+port+" does not appear to have backported security patches.");
