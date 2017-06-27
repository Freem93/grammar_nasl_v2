#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(45505);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/07/18 14:06:43 $");

  script_name(english:"Adobe Reader < 9.3.2 / 8.2.2  Multiple Vulnerabilities (APSB10-09)");
  script_summary(english:"Checks version of Adobe Reader");

  script_cve_id(
    "CVE-2010-0190",
    "CVE-2010-0191",
    "CVE-2010-0192",
    "CVE-2010-0193",
    "CVE-2010-0194",
    "CVE-2010-0195",
    "CVE-2010-0196",
    "CVE-2010-0197",
    "CVE-2010-0198",
    "CVE-2010-0199",
    "CVE-2010-0201",
    "CVE-2010-0202",
    "CVE-2010-0203",
    "CVE-2010-0204",
    "CVE-2010-1241"
  );
  script_bugtraq_id(
    39227,
    39417,
    39469,
    39470,
    39505,
    39507,
    39511,
    39514,
    39515,
    39517,
    39518,
    39520,
    39521,
    39522,
    39523,
    39524
  );
  script_osvdb_id(
    63618,
    63751,
    63752,
    63753,
    63754,
    63755,
    63756,
    63757,
    63758,
    63759,
    63760,
    63761,
    63762,
    63763,
    63764
  );

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Windows host is affected by
multiple vulnerabilities.");

  script_set_attribute(attribute:"description",value:

"The version of Adobe Reader installed on the remote host is earlier
than 9.3.2 / 8.2.2.  Such versions are reportedly affected by multiple
vulnerabilities :
  
  - A cross-site scripting issue could lead to code
    execution. (CVE-2010-0190)

  - A prefix protocol handler vulnerability could lead to
    code execution. (CVE-2010-0191)

  - A denial of service vulnerability could potentially lead
    to code execution. (CVE-2010-0192)

  - A denial of service vulnerability could potentially lead
    to code execution. (CVE-2010-0193)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2010-0194)

  - A font handling vulnerability could lead to code
    execution. (CVE-2010-0195)

  - A denial of service vulnerability could potentially lead
    lead to code execution. (CVE-2010-0196)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2010-0197)

  - A buffer overflow vulnerability could lead to code
    execution. (CVE-2010-0198)

  - A buffer overflow vulnerability could lead to code
    execution. (CVE-2010-0199)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2010-0201)

  - A buffer overflow vulnerability could lead to code
    execution. (CVE-2010-0202)

  - A buffer overflow vulnerability could lead to code
    execution. (CVE-2010-0203)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2010-0204)

  - A heap-based buffer overflow vulnerability could lead
    to code execution. (CVE-2010-1241)");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-09.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Reader 9.3.2 / 8.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies('adobe_reader_installed.nasl');
  script_require_keys('SMB/Acroread/Version');
  exit(0);
}

#

include('global_settings.inc');

info = NULL;
vers = get_kb_list('SMB/Acroread/Version');
if (isnull(vers)) exit(0, 'The "SMB/Acroread/Version" KB item is missing.');

foreach version (vers)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if  ( 
    ver[0] < 8 ||
    (ver[0] == 8 && ver[1] < 2) ||
    (ver[0] == 8 && ver[1] == 2 && ver[2] < 2) ||
    (ver[0] == 9 && ver[1] < 3) ||
    (ver[0] == 9 && ver[1] == 3 && ver[2] < 2)
  )
  {
    path = get_kb_item('SMB/Acroread/'+version+'/Path');
    if (isnull(path)) exit(1, 'The "SMB/Acroread/'+version+'/Path" KB item is missing.');

    verui = get_kb_item('SMB/Acroread/'+version+'/Version_UI');
    if (isnull(verui)) exit(1, 'The "SMB/Acroread/'+version+'/Version_UI" KB item is missing.');

    info += '  - ' + verui + ', under ' + path + '\n';
  }
}

if (isnull(info)) exit(0, 'The remote host is not affected.');

if (report_verbosity > 0)
{
  if (max_index(split(info)) > 1) s = "s of Adobe Reader are";
  else s = " of Adobe Reader is";

  report =
    '\nThe following vulnerable instance'+s+' installed on the'+
    '\nremote host :\n\n'+
    info;
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
else security_hole(get_kb_item("SMB/transport"));
