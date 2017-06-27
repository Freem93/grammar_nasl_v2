#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69803);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2012-4350");
  script_bugtraq_id(56915);
  script_osvdb_id(88465);
  script_xref(name:"IAVB", value:"2013-B-0004");

  script_name(english:"Symantec Enterprise Security Manager Unquoted Search Path (SYM12-020)");
  script_summary(english:"Checks for unquoted service");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a security application installed that uses
an unquoted service path.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Enterprise Security Manager installed on the
remote host has a service that uses an unquoted search path that
contains at least one whitespace.  A local attacker could gain elevated
privileges by inserting an executable file in the path of the affected
service.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Enterprise Security Manager 11.0 or apply the patch
in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20121213_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea3c4920");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:enterprise_security_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services_params.nasl");
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
    item = ereg_replace(pattern:'^(\\s+)?("?[A-Za-z]:\\\\[^:]+).*', string:item, replace:"\2");

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
    item = ereg_replace(pattern:'^([A-Za-z]:\\\\.*\\\\[^\\.]+\\.[^\\s]+).*', string:item, replace:"\1");
  }
  return item;
}

agentservice = get_kb_item('SMB/svc/ESMAgent/path');
managerservice = get_kb_item('SMB/svc/ESMManager/path');
if (isnull(agentservice) && isnull(managerservice)) exit(1, 'The SMB/svc/ESMAgent/path and SMB/svc/ESMManager/path services are not installed.');

paths = make_array();
if (!isnull(agentservice))
  paths['ESMAgent'] = extract_service_path(agentservice);
if (!isnull(managerservice))
  paths['ESMManager'] = extract_service_path(managerservice);

info = '';
vuln = 0;
foreach service (keys(paths))
{
  path = paths[service];
  # If there is a space in the path and it isn't enclosed in '"'
  # there is a problem
  if (' ' >< path && path !~ '^".*"$')
  {
    # Make sure the whitespace isn't only at the end of the path
    if (path !~ '^[^\\s]+\\s+$')
    {
      # Set a KB item so we can ignore this in the generic check if this
      # plugin catches it
      set_kb_item(name:"SMB/Unquoted/" + service, value:"TRUE");
      info +=
        '\n  Service name : ' + service +
        '\n  Service path : ' + path + '\n';
      vuln++;
    }
  }
}

if (info)
{
  port = get_kb_item('SMB/transport');
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = 's';
    else s = '';
    report =
      '\nNessus found the following service' + s + ' with an untrusted path : ' +
      info;

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
