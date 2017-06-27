#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25769);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2012/03/21 16:32:11 $");

  script_cve_id("CVE-2007-2513");
  script_bugtraq_id(24258);
  script_xref(name:"OSVDB", value:"35942");

  script_name(english:"Novell GroupWise Authentication Credentials MiTM Disclosure");
  script_summary(english:"Checks version of grpwise.exe");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by an
information disclosure vulnerability." );
  script_set_attribute(attribute:"description", value:
"The version of the Novell GroupWise Client installed on the remote
host reportedly allows a remote attacker to intercept authentication
credentials via a man-in-the-middle attack." );
  script_set_attribute(attribute:"see_also", value:"http://www.cirosec.de/deutsch/dienstleistungen/advisory_040607.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d714983" );
  script_set_attribute(attribute:"solution", value:
"Upgrade GroupWise clients to GroupWise 7 SP2 dated May 24, 2007 or
newer / 6.5 post-SP6 dated May 22, 2007 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/26");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/01");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");

  script_dependencies("groupwise_client_installed.nasl");
  script_require_keys("SMB/Novell GroupWise Client/Path", "SMB/Novell GroupWise Client/Version");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

version = get_kb_item_or_exit('SMB/Novell GroupWise Client/Version');
path = get_kb_item_or_exit('SMB/Novell GroupWise Client/Path');

ver = split(version, sep:'.');
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = NULL;
if (ver[0] == 7) fix = '7.0.2.562';
else if (ver[0] < 7) fix = '6.57.0.0';

if (fix && ver_compare(ver:version, fix:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_warning(get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'The Novell GroupWise Client '+version+' install under '+path+' is not affected.');
