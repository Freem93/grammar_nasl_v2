#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24002);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id(
    "CVE-2006-5857", 
    "CVE-2007-0044", 
    "CVE-2007-0045", 
    "CVE-2007-0046",
    "CVE-2007-0047", 
    "CVE-2007-0048"
  );
  script_bugtraq_id(21858, 21981);
  script_osvdb_id(31046, 31047, 31048, 31316, 31596, 34407);

  script_name(english:"Adobe Reader < 6.0.6 / 7.0.9 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(attribute:"synopsis", value:
"The PDF file viewer on the remote Windows host is affected by several
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is earlier
than 7.0.9 / 8.0 and is, therefore, reportedly affected by several 
security issues, including one that can lead to arbitrary code 
execution when processing a malicious PDF file." );
  script_set_attribute(attribute:"see_also", value:"http://www.piotrbania.com/all/adv/adobe-acrobat-adv.txt" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Jan/199" );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-01.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 6.0.6 / 7.0.9 / 8.0 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(352, 399);

  script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/10");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/27");
  script_set_attribute(attribute:"patch_publication_date", value: "2007/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
  if (ver =~ "^([0-5]\.|6\.0\.[0-5][^0-9.]?|7\.0\.[0-8][^0-9.]?)")
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
