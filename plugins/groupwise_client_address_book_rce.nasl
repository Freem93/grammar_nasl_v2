#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58402);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/05/10 22:10:39 $");

  script_cve_id("CVE-2011-4189");
  script_bugtraq_id(52233);
  script_osvdb_id(79720);

  script_name(english:"Novell GroupWise Client Address Book File Handling Email Address Field Remote Overflow");
  script_summary(english:"Checks version of grpwise.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an email application that is
affected by a remote buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Novell GroupWise Client 8.x installed on the remote
Windows host is earlier than 8.0.2 post-HP3.  As such, it is
reportedly affected by a buffer overflow vulnerability when parsing an
Address Book (.nab) file with an overly long email address. 

By tricking a user into opening a specially crafted Address Book file,
a remote, unauthenticated attacker could potentially execute arbitrary
code on the remote host subject to the privileges of the user running
the affected application.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25ae0d50");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7010205");
  script_set_attribute(attribute:"solution", value:"Upgrade to Novell GroupWise Client 8.0.2 post-HP3 (8.0.2.19083) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("groupwise_client_installed.nasl");
  script_require_keys("SMB/Novell GroupWise Client/Path", "SMB/Novell GroupWise Client/Version");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

version = get_kb_item_or_exit('SMB/Novell GroupWise Client/Version');
path = get_kb_item_or_exit('SMB/Novell GroupWise Client/Path');

fix = '8.0.2.19083';
if (version =~ '^8\\.0\\.' && ver_compare(ver:version, fix:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'The Novell GroupWise Client '+version+' install under '+path+' is not affected.');
