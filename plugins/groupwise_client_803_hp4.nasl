#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77665);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/12 13:27:45 $");

  script_cve_id("CVE-2014-0610");
  script_bugtraq_id(69649);
  script_osvdb_id(110556);

  script_name(english:"Novell GroupWise Client 8.x < 8.0.3 Hot Patch 4 / 2012 < 2012 SP3 / 2014 < 2014 SP1 Multiple Dereference Vulnerabilities");
  script_summary(english:"Checks the version of grpwise.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an email application that is affected
by multiple untrusted pointer dereference vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Novell GroupWise Client installed on the remote Windows host is
version 8.x prior to 8.0.3 Hot Patch 4 (8.0.3.36955), version 2012
prior to 2012 SP3 (12.0.3.26810), or version 2014 prior to 2014 SP1
(14.0.1.27118). It is, therefore, affected by multiple untrusted
pointer dereference vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7015565");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Novell GroupWise Client 8.0.3 Hot Patch 4 (8.0.3.36955) /
2012 SP3 (12.0.3.26810) / 2014 SP1 (14.0.1.27118) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("groupwise_client_installed.nasl");
  script_require_keys("SMB/Novell GroupWise Client/Path", "SMB/Novell GroupWise Client/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('SMB/Novell GroupWise Client/Version');
path = get_kb_item_or_exit('SMB/Novell GroupWise Client/Path');

fixed_version = '';

if (version =~ '^8\\.' && ver_compare(ver:version, fix:'8.0.3.36955') == -1)
  fixed_version = '8.0.3 Hot Patch 4 (8.0.3.36955)';
else if (version =~ '^12\\.' && ver_compare(ver:version, fix:'12.0.3.26810') == -1)
  fixed_version = '2012 SP3 (12.0.3.26810)';
else if (version =~ '^14\\.' && ver_compare(ver:version, fix:'14.0.1.27118') == -1)
  fixed_version = '2014 SP1 (14.0.1.27118)';

if (!empty(fixed_version))
{
  port = get_kb_item("SMB/transport");
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
