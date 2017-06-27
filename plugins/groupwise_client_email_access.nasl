#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22003);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-3268");
  script_bugtraq_id(18716);
  script_xref(name:"OSVDB", value:"26921");

  script_name(english:"Novell GroupWise Windows Client Arbitrary Email Access");
  script_summary(english:"Check the version of GroupWise client"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that may allow
unauthorized access to email messages." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GroupWise, an enterprise-class
collaboration application from Novell. 

The version of GroupWise installed on the remote host contains a flaw
in the client API that may allow a user to bypass security controls
and gain access to non-authorized email within the same authenticated
post office." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/10778" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to GroupWise 6.5 SP6 Update 1 / 7 SP1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/19");
 script_cvs_date("$Date: 2012/03/21 16:32:11 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

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
if (ver[0] == 7) fix = '7.0.1.364';
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
  else security_warning(port:get_kb_item('SMB/transport'));
}
else exit(0, 'The Novell GroupWise Client '+version+' install under '+path+' is not affected.');
