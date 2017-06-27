#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(52672);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2011-0609");
  script_bugtraq_id(46860);
  script_osvdb_id(71254);
  script_xref(name:"CERT", value:"192052");
  script_xref(name:"EDB-ID", value:"17027");

  script_name(english:"Adobe Reader 9.x / 10.x Unspecified Memory Corruption (APSB11-06)");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Adobe Reader on the remote Windows host is affected by
a memory corruption vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of Adobe Reader 9.x <
9.4.3 or 10.x < 10.1.  Such versions are affected by an unspecified
memory corruption vulnerability in authplay.dll. 

A remote attacker could exploit this by tricking a user into viewing
maliciously crafted SWF content, resulting in arbitrary code
execution. 

This bug is currently being exploited in the wild."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82775d9e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/advisories/apsa11-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb11-06.html"
  );
  # "The update for Adobe Reader X (10.x) for Windows also incorporate the updates
  # previously addressed in all other supported versions of Adobe Reader and Acrobat
  # as noted in Security Bulletin APSB11-06 and Security Bulletin APSB11-08."
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb11-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4711a8e"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Adobe Reader 9.4.2 / 10.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player AVM Bytecode Verification Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");

  exit(0);
}


include('global_settings.inc');

info =  '';
info2 = '';
vuln = 0;
vers = get_kb_list('SMB/Acroread/Version');
if (isnull(vers)) exit(0, 'The "SMB/Acroread/Version" KB list is missing.');

foreach version (vers)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  path = get_kb_item('SMB/Acroread/'+version+'/Path');
  if (isnull(path)) path = 'n/a';

  verui = get_kb_item('SMB/Acroread/'+version+'/Version_UI');
  if (isnull(verui)) verui = version;

  if (
    (ver[0] == 9 && ver[1]  < 4) ||
    (ver[0] == 9 && ver[1] == 4 && ver[2] < 3) ||
    (ver[0] == 10 && ver[1] < 1)
  )
  {
    vuln++;
    info += '\n  Path              : '+path+
            '\n  Installed version : '+verui+
            '\n  Fixed version     : 9.4.3 / 10.1\n';
  }
  else
    info2 += " and " + verui;
}

if (info)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Adobe Reader are";
    else s = " of Adobe Reader is";

    report =
      '\nThe following vulnerable instance'+s+' installed on the'+
      '\nremote host :\n'+
      info;
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}

if (info2)
{
  info2 -= " and ";
  if (" and " >< info2) be = "are";
  else be = "is";

  exit(0, "The host is not affected since Adobe Reader "+info2+" "+be+" installed.");
}
else exit(1, "Unexpected error - 'info2' is empty.");

