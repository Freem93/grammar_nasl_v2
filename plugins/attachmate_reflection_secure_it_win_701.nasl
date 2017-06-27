#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(55285);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_cve_id("CVE-2008-6021");
  script_bugtraq_id(30723);
  script_osvdb_id(48607);

  script_name(english:"Attachmate Reflection for Secure IT Windows Server < 7.0 SP1 Multiple Unspecified Vulnerabilities");
  script_summary(english:"Checks version of Attachmate Reflection for Secure IT");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is affected by multiple unspecified
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Attachmate Reflection for Secure IT Windows server
installed on the remote Windows host is less than 7.0 SP1 and thus is
reportedly affected by multiple unspecified vulnerabilities.");
 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28170386");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Attachmate Reflection for Secure IT Windows Server 7.0 SP1
(7.0.0 Build 505) or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:attachmate:reflection_for_secure_it");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("attachmate_reflection_secure_it_win_installed.nasl");
  script_require_keys("SMB/Attachmate_Reflection_For_Secure_IT/path");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

verui   = get_kb_item_or_exit('SMB/Attachmate_Reflection_For_Secure_IT/verui');
path    = get_kb_item_or_exit('SMB/Attachmate_Reflection_For_Secure_IT/path');

version = verui - strstr(verui, ' Build');
build   = strstr(verui, 'Build');
build   = ereg_replace(pattern:'^Build ([0-9]+)', string:build, replace:'\\1');
ver = split(version, sep:'.', keep:FALSE);

if (
  ver[0] < 7 ||
  (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && build < 505)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version + ' Build ' + build +
      '\n  Fixed version     : 7.0.0 Build 505\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'Attachmate Reflection for Secure IT '+verui+' is installed and thus is not affected.');
