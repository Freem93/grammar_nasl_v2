#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(0);
include('compat.inc');


if (description)
{
  script_id(42120);
  script_version('$Revision: 1.23 $');
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id(
    "CVE-2007-0048",
    "CVE-2007-0045",
    "CVE-2009-2564",
    "CVE-2009-2979",
    "CVE-2009-2980",
    "CVE-2009-2981",
    "CVE-2009-2982",
    "CVE-2009-2983",
    "CVE-2009-2986",
    "CVE-2009-2987",
    "CVE-2009-2988",
    "CVE-2009-2990",
    "CVE-2009-2991",
    "CVE-2009-2992",
    "CVE-2009-2993",
    "CVE-2009-2994",
    "CVE-2009-2996",
    "CVE-2009-2997",
    "CVE-2009-2998",
    "CVE-2009-3431",
    "CVE-2009-3458",
    "CVE-2009-3459"
  );
  script_bugtraq_id(
    21858,
    35740,
    36600,
    36664,
    36665,
    36667,
    36668,
    36669,
    36671,
    36677,
    36678,
    36680,
    36681,
    36682,
    36683,
    36686,
    36687,
    36688,
    36689,
    36690,
    36692,
    36695
  );
  script_osvdb_id(
    31046,
    31596,
    56120,
    58415,
    58729,
    58906,
    58907,
    58908,
    58909,
    58910,
    58911,
    58912,
    58913,
    58916,
    58920,
    58921,
    58923,
    58925,
    58926,
    58927,
    58928,
    58929
  );
  script_xref(name:"Secunia", value:"36983");

  script_name(english:"Adobe Reader < 9.2 / 8.1.7 / 7.1.4  Multiple Vulnerabilities (APSB09-15)");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(attribute:"synopsis", value:
"The PDF file viewer on the remote Windows host is affected by a
memory corruption vulnerability."  );
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is earlier
than 9.2 / 8.1.7 / 7.1.4.  Such versions are potentially affected by
multiple vulnerabilities :

  - A heap overflow vulnerability. (CVE-2009-3459)

  - A memory corruption issue. (CVE-2009-2985)

  - Multiple heap overflow vulnerabilities. (CVE-2009-2986)

  - An invalid array index issue that could lead to code
    execution. (CVE-2009-2990)

  - Multiple input validation vulnerabilities that could
    lead to code execution. (CVE-2009-2993)

  - A buffer overflow issue. (CVE-2009-2994)

  - A heap overflow vulnerability. (CVE-2009-2997)

  - An input validation issue that could lead to code
    execution. (CVE-2009-2998)

  - An input validation issue that could lead to code
    execution. (CVE-2009-3458)

  - A memory corruption issue that leads to a denial of
    service. (CVE-2009-2983)

  - An integer overflow that leads to a denial of service.
    (CVE-2009-2980)

  - A memory corruption issue that leads to a denial of
    service. (CVE-2009-2996)

  - An input validation issue that could lead to a bypass
    of Trust Manager restrictions. (CVE-2009-2981)

  - A certificate is used that, if compromised, could be used
    in a social engineering attack. (CVE-2009-2982)

  - A stack overflow issue that could lead to a denial of
    service. (CVE-2009-3431)

  - A XMP-XML entity expansion issue that could lead to a
    denial of service attack. (CVE-2009-2979)

  - A remote denial of service issue in the ActiveX control.
    (CVE-2009-2987)

  - An input validation issue. (CVE-2009-2988)

  - An input validation issue specific to the ActiveX
    control. (CVE-2009-2992)

  - A third-party web download product is used that could
    lead to a local privilege escalation. (CVE-2009-2564)

  - A cross-site scripting issue when the browser plugin in
    used with Google Chrome and Opera browsers.
    (CVE-2007-0048, CVE-2007-0045)" );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.adobe.com/support/security/bulletins/apsb09-15.html'
  );
  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to Adobe Reader 9.2 / 8.1.7 / 7.1.4 or later.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe FlateDecode Stream Predictor 02 Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 119, 189, 264, 310, 399);
script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies('adobe_reader_installed.nasl');
  script_require_keys('SMB/Acroread/Version');

  exit(0);
}


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
    ver[0] < 7 ||
    (
      ver[0] == 7 &&
      (
        ver[1] < 1 ||
        (ver[1] == 1 && ver[2] < 4)
      )
    ) ||
    (
      ver[0] == 8 &&
      (
        ver[1] < 1 ||
        (ver[1] == 1 && ver[2] < 7)
      )
    ) ||
    (
      ver[0] == 9 &&  ver[1] < 2
    )
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
