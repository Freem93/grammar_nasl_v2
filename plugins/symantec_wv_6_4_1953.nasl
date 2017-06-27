#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72219);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/01/31 01:35:20 $");

  script_cve_id("CVE-2013-4679");
  script_bugtraq_id(61349);
  script_osvdb_id(95459);

  script_name(english:"Symantec Workspace Virtualization 6.x < 6.4.1953 Local Privilege Escalation (SYM13-011)");
  script_summary(english:"Check Symantec Workspace Virtualization version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application installed on the remote host is affected by a local
privilege escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of Symantec Workspace
Virtualization 6.x prior to 6.4.1953.  It is, therefore, affected by a
local privilege escalation vulnerability due to a failure to sanitize
user-supplied input.  An attacker could potentially exploit this
vulnerability to run arbitrary code with SYSTEM level privileges. 

Note that the vulnerability is only exploitable if at least one virtual
application layer is activated/enabled."
  );
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20130801_02
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7101468b");
  # http://www.symantec.com/business/support/index?page=content&id=HOWTO85016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c3a6727");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 6.4.1953 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:workspace_virtualization");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("symantec_wv_installed.nbin");
  script_require_keys("SMB/symantec_workspace_virtualization/path", "SMB/symantec_workspace_virtualization/version", "SMB/symantec_workspace_virtualization/active_app_layers");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = 'Symantec Workspace Virtualization';
version = get_kb_item_or_exit('SMB/symantec_workspace_virtualization/version');
path = get_kb_item_or_exit('SMB/symantec_workspace_virtualization/path');
active_app_layers = get_kb_item_or_exit('SMB/symantec_workspace_virtualization/active_app_layers');

if (active_app_layers < 1) audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

fixed_version = '6.4.1953.0';
min_version = '6.0';

if (
  ver_compare(ver:version, fix:min_version, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
    '\n  Path              : ' + path +
    '\n  Active App Layers : ' + active_app_layers +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
