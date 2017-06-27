#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83117);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/29 13:26:12 $");

  script_cve_id("CVE-2015-1484");
  script_bugtraq_id(73925);
  script_osvdb_id(120893);

  script_name(english:"Symantec Workspace Streaming Agent Unquoted Service Path Local Privilege Escalation (SYM15-004)");
  script_summary(english:"Checks for unquoted service.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that uses an unquoted service
path.");
  script_set_attribute(attribute:"description", value:
"The version of the Symantec Workspace Streaming (SWS) agent installed
on the remote Windows host is affected by a local privilege escalation
vulnerability due to an unquoted search path in AppMgrService.exe. A
local attacker can exploit this to execute arbitrary code with local
system privileges.

Note that Symantec Workspace Streaming was formerly known as Altiris
Streaming System.");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20150410_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a67e480");
  script_set_attribute(attribute:"solution", value:
"Upgrade SWS agents to 6.1 SP8 MP2 HF7 / 7.5 SP1 HF4 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:symantec:workspace_streaming_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:workspace_streaming");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services_params.nasl");
  script_require_keys("SMB/Services/Enumerated", "SMB/svc/AppMgrService/path");
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

agentservice = get_kb_item_or_exit('SMB/svc/AppMgrService/path');

path = extract_service_path(agentservice);

# If there is a space in the path and it isn't enclosed in '"'
# there is a problem
if (' ' >< path && path !~ '^".*"$')
{
  # Make sure the whitespace isn't only at the end of the path
  if (path !~ '^[^\\s]+\\s+$')
  {
    # Set a KB item so we can ignore this in the generic check if this
    # plugin catches it
    set_kb_item(name:"SMB/Unquoted/AppMgrService", value:"TRUE");

    port = get_kb_item('SMB/transport');
    if (isnull(port)) port = 445;

    if (report_verbosity > 0)
    {
      report =
        '\nNessus found the following service with an untrusted path : ' +
        '\n  Service name : AppMgrService ' +
        '\n  Service path : ' + path + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_HOST_NOT, 'affected');
