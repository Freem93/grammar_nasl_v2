#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(62412);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/02/05 12:38:14 $");

  script_cve_id("CVE-2012-0418");
  script_bugtraq_id(55729);
  script_osvdb_id(85802);

  script_name(english:"Novell GroupWise Client 8.x < 8.0.3 / 2012.x < 2012 SP1 Unspecified File Handling Arbitrary Code Execution");
  script_summary(english:"Checks version of grpwise.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an email application that is affected
by an unspecified code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Novell GroupWise Client installed on the remote Windows
host is 8.x earlier than 8.0.3 (8.0.3.21955) or 2012.x earlier than 2012
SP1 (12.0.1.13731).  As such, it is reportedly affected by an
unspecified code execution vulnerability. 

By tricking a user into opening a specially crafted file, a remote,
unauthenticated attacker could potentially execute arbitrary code on the
remote host subject to the privileges of the user running the affected
application.");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7010771");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Novell GroupWise Client 8.0.3 (8.0.3.21955) / 2012 SP1
(12.0.1.13731) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("groupwise_client_installed.nasl");
  script_require_keys("SMB/Novell GroupWise Client/Path", "SMB/Novell GroupWise Client/Version");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

version = get_kb_item_or_exit('SMB/Novell GroupWise Client/Version');
path = get_kb_item_or_exit('SMB/Novell GroupWise Client/Path');

if (version =~ '^8\\.' && ver_compare(ver:version, fix:'8.0.3.21955') == -1)
  fixed_version = '8.0.3 (8.0.3.21955)';
else if (version =~ '^12\\.' && ver_compare(ver:version, fix:'12.0.1.13731') == -1)
  fixed_version = '2012 SP1 (12.0.1.13731)';

if (fixed_version)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Novell GroupWise Client', version, path);
