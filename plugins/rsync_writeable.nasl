#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78428);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/01/15 21:39:12 $");

  script_name(english:"rsync Writeable Module Detection");
  script_summary(english:"Shows the remotely writeable rsync modules.");

  script_set_attribute(attribute:"synopsis", value:
"The remote synchronization service is remotely writeable.");
  script_set_attribute(attribute:"description", value:
"The rsync server on the host can be remotely written to.");
  script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Rsync");
  script_set_attribute(attribute:"solution", value:
"Limit access to the service if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/rsyncd", 873);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("string.inc");
include("rsync.inc");

port = get_service(svc:"rsyncd", default:873, exit_on_fail:TRUE);

soc = rsync_init(port:port, exit_if_fail:TRUE);
modules = rsync_list_modules(socket:soc);
close(soc);

if (isnull(modules)) audit(AUDIT_LISTEN_NOT_VULN, "Rsync daemon", port);

writeable_count = 0;
report = NULL;

foreach module (modules)
{
  m = split(module, sep:'\x00', keep:FALSE);
  name = m[0];
  comment = m[1];
  soc = rsync_init(port:port);
  if (soc)
  {
    if (rsync_test_put_file(socket:soc, module:name, file_name:"nessus.test"))
    {
      # writeable!
      report += '\n  - ' + name + " (" + comment + ")";
      set_kb_item(name:"rsyncd/" + port + "/writeable/" + writeable_count, value:base64(str:name));
      writeable_count++;
    }
    close(soc);
  }
}

if (isnull(report)) audit(AUDIT_LISTEN_NOT_VULN, "Rsync Daemon", port);

if (report_verbosity > 0)
{
  report = '\n' + 'The following rsync modules are writeable by anyone :' +
           '\n' + report + 
           '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
