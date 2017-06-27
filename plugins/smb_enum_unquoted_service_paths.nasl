#
# (C) Tenable Network Security, Inc
#

include("compat.inc");

if (description)
{
  script_id(63155);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id("CVE-2013-1609", "CVE-2014-0759", "CVE-2014-5455");
  script_bugtraq_id(58591, 58617, 65873, 68520);
  script_osvdb_id(91492, 91582, 102505, 109007, 132967);
  script_xref(name:"ICSA", value:"14-058-01");
  script_xref(name:"EDB-ID", value:"34037");

  script_name(english:"Microsoft Windows Unquoted Service Path Enumeration");
  script_summary(english:"Generic check for unquoted service paths.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has at least one service installed that uses
an unquoted service path.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has at least one service installed that uses
an unquoted service path, which contains at least one whitespace. A
local attacker can gain elevated privileges by inserting an executable
file in the path of the affected service.

Note that this is a generic test that will flag any application
affected by the described vulnerability.");
  # https://isc.sans.edu/diary/Help+eliminate+unquoted+path+vulnerabilities/14464
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84a4cc1c");
  script_set_attribute(attribute:"see_also", value:"http://cwe.mitre.org/data/definitions/428.html");
  script_set_attribute(attribute:"see_also", value:"https://www.commonexploits.com/unquoted-service-paths/");
  # http://www.ryanandjeffshow.com/blog/2013/04/11/powershell-fixing-unquoted-service-paths-complete/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4aa6acbc");
  script_set_attribute(attribute:"solution", value:
"Ensure that any services that contain a space in the path enclose the
path in quotes.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:X/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Windows Service Trusted Path Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services_params.nasl", "symantec_encryption_desktop_sym13-010.nasl", "symantec_enterprise_security_manager_sym12-020.nasl", "symantec_wsa_sym15-004.nasl");
  script_require_keys("SMB/Services/Enumerated");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("smb_header.inc");

function extract_service_path()
{
  local_var item, idx;

  item = _FCT_ANON_ARGS[0];
  # If the first character is a '"', the path is enclosed, so just use
  # that to extract the path
  if (item =~ '^"')
  {
    item = ereg_replace(pattern:'^("[^"]+").*', string:item, replace:"\1");
  }
  else
  {
    # First extract any extra paths from the arguments
    item = ereg_replace(pattern:'^(\\s+)?("?([A-Za-z]:|\\\\)\\\\[^:]+).*', string:item, replace:"\2");

    # Service arguments use '-' or '/' characters for flags
    # First look for '/' flags
    if ('/' >< item)
    {
      idx = stridx(item, '/');
      item = item - substr(item, idx);
    }

    # Now look for ' -' flags
    if (' -' >< item)
    {
      idx = stridx(item, ' -');
      item = item - substr(item, idx);
    }

    # Some arguments don't use a flag
    item = ereg_replace(pattern:'^(([A-Za-z]:|\\\\)\\\\.*\\\\[^\\.]+\\.[^\\s]+).*', string:item, replace:"\1");
  }
  return item;
}

slist = get_kb_list_or_exit('SMB/svc/*/startuptype');
services = make_list();

# Unless we are paranoid, only focus on the services that
# aren't disabled
if (report_paranoia < 2)
{
  foreach service (keys(slist))
  {
    if (slist[service] == 2 || slist[service] == 3)
    {
      services = make_list(services, service - 'SMB/svc/' - '/startuptype');
    }
  }
}
else
{
  foreach service (keys(slist))
  {
    services = make_list(services, service - 'SMB/svc/' - '/startuptype');
  }
}

# Ignore services that we are explicitly checking in other
# plugins
items = get_kb_list('SMB/Unquoted/*');
unquoted = make_array();
if (!isnull(items))
{
  foreach key (keys(items))
  {
    key = key - 'SMB/Unquoted/';
    unquoted[key] = TRUE;
  }
}
# Loop over the services and check the executable path
path = '';
info = '';
for (i=0; i < max_index(services); i++)
{
  # We have a separate check for the PGP RDD Service
  service = services[i];
  if (unquoted[service]) continue;

  item = get_kb_item('SMB/svc/'+services[i]+'/path');
  if (isnull(item)) continue;
  # Parse the service to get the path
  path = extract_service_path(item);

  # If there is a space in the path and it isn't enclosed in '"'
  # there is a problem
  if (' ' >< path && path !~ '^".*"$')
  {
    # Make sure the whitespace isn't only at the end of the path
    if (path !~ '^[^\\s]+\\s+$')
    {
      info += '  ' + services[i] + ' : ' + path + '\n';
    }
  }
}

if (info)
{
  port = get_kb_item('SMB/transport');
  if (report_verbosity > 0)
  {
    if (max_index(split(info, sep:'\n')) > 1) s = 's ';
    else s = ' ';

    report =
      '\nNessus found the following service' + s + 'with an untrusted path : ' +
      '\n' +
      info +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
