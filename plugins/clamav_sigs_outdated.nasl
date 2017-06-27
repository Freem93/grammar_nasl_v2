#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46172);
  script_version("$Revision: 1.924 $");
  script_cvs_date("$Date: 2016/06/30 20:19:09 $");

  script_name(english:"ClamAV Antivirus Detection and Status");
  script_summary(english:"Checks if the latest daily.cvd is being used.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"ClamAV antivirus is installed on the remote host. However, there is a
problem with the installation; either its services are not running or
its engine and/or virus definitions are out of date. In this case, the
file daily.cvd was found to be out of date.");
  script_set_attribute(attribute:"see_also", value:"http://www.clamav.net/documents/installing-clamav");
  # https://web.archive.org/web/20100621053704/http://www.clamav.net/doc/latest/html/node24.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f352bef9");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_require_ports("Services/clamd", 3310);
  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/sigs");

  exit(0);
}


include("antivirus.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:'clamd', default:3310, exit_on_fail:TRUE);

sigs = get_kb_item('Antivirus/ClamAV/sigs');
if (isnull(sigs)) exit(0, "The 'Antivirus/ClamAV/sigs' KB item is missing.");
if (int(sigs) == 0) exit(1, "The 'Antivirus/ClamAV/sigs' KB item is not valid ("+sigs+").");

info = get_av_info("clamav");
if (isnull(info)) exit(1, "Failed to get ClamAV signature info from antivirus.inc.");
last_sigs = info["last_sigs"];
last_date = info["last_date"];

if (sigs < int(last_sigs))
{
  if (report_verbosity > 0)
  {
    report =
      '\nThe remote host has an outdated version of ClamAV virus database '+
      '\n(daily.cvd) :\n'+
      '\n  Current version   : '+sigs+
      '\n  Latest version    : '+last_sigs+
      '\n  Latest published  : '+last_date+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'ClamAV virus database version '+sigs+' is up to date.');
