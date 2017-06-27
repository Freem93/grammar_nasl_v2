#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21737);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/10/07 19:48:35 $");

  script_cve_id("CVE-2006-3015");
  script_bugtraq_id(18384);
  script_osvdb_id(26338);

  script_name(english:"WinSCP URI Handler Arbitrary File Access");
  script_summary(english:"Checks version of WinSCP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that allows arbitrary file
access.");
  script_set_attribute(attribute:"description", value:
"According to its version, the WinSCP install on the remote host allows
a remote attacker to automatically initiate a file transfer to or from
the affected host or to append log information to an existing file,
provided that the user can be tricked into clicking on a malicious
link.");
  script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-June/046810.html");
  script_set_attribute(attribute:"see_also", value:"http://winscp.net/eng/docs/history#3.8.2");
  script_set_attribute(attribute:"solution", value:"Upgrade to WinSCP version 3.8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winscp:winscp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");

  script_dependencies("winscp_installed.nbin");
  script_require_keys("installed_sw/WinSCP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'WinSCP';
fixed_version = '3.8.2';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + 
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
