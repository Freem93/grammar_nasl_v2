#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');


if (description)
{
  script_id(40494);
  script_version('$Revision: 1.19 $');
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id('CVE-2009-1862');
  script_bugtraq_id(35759);
  script_osvdb_id(56282);

  script_name(english:'Adobe Reader < 9.1.3 Flash Handling Unspecified Arbitrary Code Execution (APSB09-10)');
  script_summary(english:'Checks version of Adobe Reader');

  script_set_attribute(attribute:'synopsis', value:
'The PDF file viewer on the remote Windows host is affected by a
memory corruption vulnerability.');
  script_set_attribute(attribute:'description', value:
'The version of Adobe Reader 9 installed on the remote host is earlier
than 9.1.3.  Such versions are reportedly affected by a memory corruption
vulnerability that could potentially lead to code execution.'  );
  script_set_attribute(
    attribute:'see_also',
    value:'http://www.adobe.com/support/security/bulletins/apsb09-10.html'
  );
  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to Adobe Reader 9.1.3 or later.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_publication_date", value: "2009/08/05");
  script_set_attribute(attribute:"patch_publication_date", value: "2009/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');

  script_copyright(english:"(C) 2009-2016 Tenable Network Security, Inc.");

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

  if  ( ver[0] == 9 && ( ver[1] < 1 || (ver[1] == 1 && ver[2] < 3) ) )
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
