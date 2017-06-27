#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38746);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2009-1492");
  script_bugtraq_id(34736);
  script_osvdb_id(54130);
  script_xref(name:"CERT", value:"970180");
  script_xref(name:"Secunia", value:"34924");

  script_name(english:"Adobe Reader getAnnots() JavaScript Method PDF Handling Memory Corruption (APSB09-06)");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(attribute:"synopsis", value:
"The PDF file viewer on the remote Windows host is affected by a memory
corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is earlier
than 9.1.1 / 8.1.5 / 7.1.2.  Such versions reportedly fail to validate
input from a specially crafted PDF file before passing it to the
JavaScript method 'getAnnots()' leading to memory corruption and
possibly arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa09-02.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb09-06.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Reader 9.1.1 / 8.1.5 / 7.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");

  exit(0);
}


include("global_settings.inc");


info = NULL;
vers = get_kb_list('SMB/Acroread/Version');
if (isnull(vers)) exit(0, 'The "SMB/Acroread/Version" KB item is missing.');

foreach ver (vers)
{
  if (
    ver && 
    (
      ver =~ "^[0-6]\." ||
      ver =~ "^7\.(0\.|1\.[01]($|[^0-9]))" ||
      ver =~ "^8\.(0\.|1\.[0-4]($|[^0-9]))" ||
      ver =~ "^9\.(0\.|1\.0($|[^0-9]))"
    )
  )
  {
    path = get_kb_item('SMB/Acroread/'+ver+'/Path');
    if (isnull(path)) exit(1, 'The "SMB/Acroread/'+ver+'/Path" KB item is missing.');

    verui = get_kb_item('SMB/Acroread/'+ver+'/Version_UI');
    if (isnull(verui)) exit(1, 'The "SMB/Acroread/'+ver+'/Version_UI" KB item is missing.');

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
