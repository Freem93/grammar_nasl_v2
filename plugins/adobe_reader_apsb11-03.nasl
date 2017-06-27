#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(51925);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/04 14:21:27 $");

  script_cve_id("CVE-2010-4091", "CVE-2011-0558", "CVE-2011-0559", 
                "CVE-2011-0560", "CVE-2011-0561", "CVE-2011-0562", 
                "CVE-2011-0563", "CVE-2011-0564", "CVE-2011-0565", 
                "CVE-2011-0566", "CVE-2011-0567", "CVE-2011-0570", 
                "CVE-2011-0571", "CVE-2011-0572", "CVE-2011-0573", 
                "CVE-2011-0574", "CVE-2011-0575", "CVE-2011-0577", 
                "CVE-2011-0578", "CVE-2011-0585", "CVE-2011-0586", 
                "CVE-2011-0587", "CVE-2011-0588", "CVE-2011-0589", 
                "CVE-2011-0590", "CVE-2011-0591", "CVE-2011-0592", 
                "CVE-2011-0593", "CVE-2011-0594", "CVE-2011-0595", 
                "CVE-2011-0596", "CVE-2011-0598", "CVE-2011-0599", 
                "CVE-2011-0600", "CVE-2011-0602", "CVE-2011-0603", 
                "CVE-2011-0604", "CVE-2011-0606", "CVE-2011-0607", 
                "CVE-2011-0608");

  script_bugtraq_id(
    44638,
    46186,
    46187,
    46188,
    46189,
    46190,
    46191,
    46192,
    46193,
    46194,
    46195,
    46196,
    46197,
    46198, 
    46199,
    46201,
    46202,
    46204,
    46207,
    46208,
    46209,
    46210,
    46211,
    46212,
    46213,
    46214,
    46216,
    46217,
    46218,
    46219,
    46220,
    46221,
    46222,
    46251,
    46252,
    46254,
    46255,
    46257,
    46282,
    46283
  );
  script_osvdb_id(
    69005,
    70911,
    70913,
    70914,
    70915,
    70916,
    70917,
    70918,
    70919,
    70920,
    70921,
    70922,
    70923,
    70976,
    71373,
    71374,
    71375,
    71376,
    71377,
    71379,
    71380,
    71381,
    71382,
    71383,
    71384,
    71385,
    71386,
    71387,
    71388,
    71389,
    71390,
    71391,
    71392,
    71393,
    71394,
    71395,
    71397,
    71398,
    71399,
    71400,
    72501
  );
                    
  script_name(english:"Adobe Reader < 10.0.1 / 9.4.2 / 8.2.6 Multiple Vulnerabilities (APSB11-03)");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Windows host is affected by
multiple vulnerabilities.");

  script_set_attribute(attribute:"description",value:
"The version of Adobe Reader installed on the remote host is earlier
than 10.0.1 / 9.4.2 / 8.2.6.  Such versions are reportedly affected by
multiple vulnerabilities :

  - Multiple input validation vulnerability exist that could
    lead to code execution. (CVE-2010-4091, CVE-2011-0586,
    CVE-2011-0587, CVE-2011-0604)
    
  - Multiple library loading vulnerabilities exist that 
    could lead to code execution. (CVE-2011-0562, 
    CVE-2011-0570, CVE-2011-0575, CVE-2011-0588)
    
  - Multiple memory corruption vulnerabilities exist that 
    could lead to code execution. (CVE-2011-0563, 
    CVE-2011-0559, CVE-2011-0560, CVE-2011-0561,
    CVE-2011-0571, CVE-2011-0572, CVE-2011-0573,
    CVE-2011-0574, CVE-2011-0578, CVE-2011-0589,
    CVE-2011-0606, CVE-2011-0607, CVE-2011-0608)
    
  - A Windows-only file permissions issue exists that could 
    lead to privilege escalation. (CVE-2011-0564)
    
  - An unspecified vulnerability exists that could cause the
    application to crash or potentially lead to code 
    execution. (CVE-2011-0565)
    
  - Multiple image-parsing memory corruption vulnerabilities 
    exist that could lead to code execution. (CVE-2011-0566, 
    CVE-2011-0567, CVE-2011-0596, CVE-2011-0598,
    CVE-2011-0599, CVE-2011-0602, CVE-2011-0603)

  - An unspecified vulnerability exists that could cause the
    application to crash or potentially lead to code
    execution. (CVE-2011-0585)

  - Multiple 3D file parsing input validation 
    vulnerabilities exist that could lead to code execution.
    (CVE-2011-0590, CVE-2011-0591, CVE-2011-0592,
     CVE-2011-0593, CVE-2011-0595, CVE-2011-0600)
  
  - Multiple font parsing input validation vulnerabilities 
    exist that could lead to code execution. (CVE-2011-0594,
    CVE-2011-0577)

  - An integer overflow vulnerability exists that could lead 
    to code execution. (CVE-2011-0558)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-065");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-066");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-067");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-068");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-069");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-070");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-071");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-072");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-073");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-074");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-075");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-077");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-081");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-03.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Reader 8.2.6, 9.4.2, 10.0.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies('adobe_reader_installed.nasl');
  script_require_keys('SMB/Acroread/Version');
  exit(0);
}

#

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
    ver[0]  < 8 ||
    (ver[0] == 8 && ver[1]  < 2) ||
    (ver[0] == 8 && ver[1] == 2  && ver[2] < 6) ||
    (ver[0] == 9 && ver[1]  < 4) ||
    (ver[0] == 9 && ver[1] == 4 && ver[2] < 2) ||
    (ver[0] == 10 && ver[1] == 0 && ver[2] < 1)
  )
  {
    vuln++;
    info += '\n  Path              : '+path+
            '\n  Installed version : '+verui+
            '\n  Fixed version     : 8.2.6 / 9.4.2 / 10.0.1\n';
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
