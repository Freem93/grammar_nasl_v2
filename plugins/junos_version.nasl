#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(55932);
 script_version("$Revision: 1.5 $");
 script_cvs_date("$Date: 2016/11/04 22:06:41 $");

 script_name(english:"Junos Version Detection");
 script_summary(english:"Obtains the version of the remote Junos device using SSH / SNMP / HTTP");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the operating system version number of the
remote Juniper device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Junos, an operating system for Juniper
devices. 

It is possible to read the Junos version number by logging into the
device via SSH, using SNMP, or viewing the web interface.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
 script_family(english:"Junos Local Security Checks");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "os_fingerprint.nasl");
 script_require_ports("Host/Juniper/show_ver", "SNMP/sysDesc", "Host/OS");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");
include("http.inc");

# 1. SSH

showver = get_kb_item("Host/Juniper/show_ver");

if (showver)
{
  model = eregmatch(string:showver, pattern:'Model: (.+)');
  version = eregmatch(string:showver, pattern:"KERNEL ([^ ]+) .+on ([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])");

  if (model && version)
  {
    set_kb_item(name:"Host/Juniper/model", value:toupper(model[1]));
    set_kb_item(name:"Host/Juniper/JUNOS/Version", value:version[1]);
    set_kb_item(name:"Host/Juniper/JUNOS/BuildDate", value:version[2]);

    if (report_verbosity > 0)
    {
      report =
        '\n  Junos version : ' + version[1] +
        '\n  Build date    : ' + version[2] +
        '\n  Model         : ' + toupper(model[1]) +
        '\n  Source        : SSH\n';
      security_note(port:0, extra:report);
    }
    else security_note(0);

    exit(0);
  }
}

# 2. SNMP

desc = get_kb_item("SNMP/sysDesc");

if (desc)
{
  junos = eregmatch(string:desc, pattern:"JUNOS ([0-9.]+[^ ]+)");
  build = eregmatch(string:desc, pattern:"Build date: ([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])");

  # if the Junos version was obtained via SNMP, try to get the model as well
  if (junos && build)
  {
    set_kb_item(name:"Host/Juniper/JUNOS/Version", value:junos[1]);
    set_kb_item(name:"Host/Juniper/JUNOS/BuildDate", value:build[1]);

    community = get_kb_item_or_exit("SNMP/community");
    port = get_kb_item("SNMP/port");
    if(!port) port = 161;
    if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
    soc = open_sock_udp(port);
    if (!soc) exit (0, "Failed to open a socket on port "+port+".");
    device = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.2636.3.1.2.0");
    close(soc);

    if (device)
    {
      # e.g. Juniper J2350 Internet Router
      model = eregmatch(string:device, pattern:"^Juniper ([^ ]+)");
      if (model)
        set_kb_item(name:"Host/Juniper/model", value:toupper(model[1]));
      else
        model = 'n/a';
    }

    if (report_verbosity > 0)
    {
      report =
        '\n  Junos version : ' + junos[1] +
        '\n  Build date    : ' + build[1] +
        '\n  Model         : ' + model[1] +
        '\n  Source        : SNMP\n';
      security_note(port:0, extra:report);
    }
    else security_note(0);

    exit(0);
  }
}

# 3. Web (only older versions allow us to view the version w/o authenticating)

os = get_kb_item_or_exit('Host/OS');
if ('junos' >!< tolower(os)) exit(0, 'The host wasn\'t fingerprinted as Junos.');

ports = get_kb_list('Services/www');
if (isnull(ports)) exit(0, 'The "Services/www" KB item is missing.');

foreach port (ports)
{
  res = http_send_recv3(method:'GET', item:'/login', port:port, exit_on_fail:TRUE);
  match = eregmatch(string:res[2], pattern:'<div class="jweb-title uppercase">.* - ([^<]+)</div>');
  if (isnull(match)) continue;
  else model = toupper(match[1]);

  set_kb_item(name:"Host/Juniper/model", value:model);

  res = http_send_recv3(method:'GET', item:'/about', port:port, exit_on_fail:TRUE);
  match = eregmatch(string:res[2], pattern:'Version (.+) *built by [^ ]+ on ([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])');
  if (isnull(match)) exit(0, 'Unable to get Junos version from the web interface, authentication may be required.');

  junos = match[1];
  build = match[2];
  set_kb_item(name:"Host/Juniper/JUNOS/Version", value:junos);
  set_kb_item(name:"Host/Juniper/JUNOS/BuildDate", value:build);

  if (report_verbosity > 0)
  {
    report =
      '\n  Junos version : ' + junos +
      '\n  Build date    : ' + build +
      '\n  Model         : ' + model +
      '\n  Source        : HTTP\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);

  exit(0);
}

exit(0, "The Junos version is not available.");
