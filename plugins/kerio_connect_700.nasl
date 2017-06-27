#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(47140);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/08/16 22:13:12 $");

  script_bugtraq_id(40505);
  script_xref(name:"Secunia", value:"39995");
  script_xref(name:"OSVDB", value:"65114");

  script_name(english:"Kerio Connect < 7.0.0 Products Administration Console File Disclosure and Corruption Vulnerabilities");
  script_summary(english:"Checks for Kerio Connect < 7.0.0");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by file disclosure and corruption
vulnerabilities." );

 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
Kerio Connect (or Kerio MailServer as it was formerly known) prior to
7.0.0.  Successful exploitation of remote file disclosure and
corruption vulnerabilities in the administration console of such
versions could allow an attacker to disclose potentially sensitive
information and manipulate data." );
  script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/support/security-advisories#1006" );
  script_set_attribute(attribute:"solution", value:"Upgrade to Kerio Connect 7.0.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/06/01");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/02/09"); # Kerio Connect 7.0.0 release date
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/25");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:connect");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("kerio_kms_641.nasl", "kerio_mailserver_admin_port.nasl");
  script_require_keys("kerio/port");
  script_require_ports("Services/kerio_mailserver_admin", "Settings/ParanoidReport");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item('kerio/port');
if (isnull(port)) exit(1, "The 'kerio/port' KB item is missing.");

if (report_paranoia < 2)
{
  get_service(svc:"kerio_mailserver_admin", exit_on_fail:TRUE);
}

service = get_kb_item('kerio/'+port+'/service');
ver = get_kb_item('kerio/'+port+'/version');
display_ver = get_kb_item('kerio/'+port+'/display_version');

# There's a problem if the version is < 7.0.0
iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

fix = split("7.0.0", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(iver); i++)
  if ((iver[i] < fix[i]))
  {
	
    if (report_verbosity)
    {
      report =
        '\n' +
        'According to its ' + service + ' banner, the remote host is running Kerio' + '\n' +
        'MailServer version ' + display_ver + '.\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
    # never reached
  }
  else if (iver[i] > fix[i])
    break;

exit(0, 'Kerio MailServer '+display_ver+' is not affected.');
