#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21698);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2013/05/13 21:33:19 $");

  script_cve_id("CVE-2006-3093");
  script_bugtraq_id(18445);
  script_osvdb_id(26535, 26536);

  script_name(english:"Adobe Reader < 7.0.8 Multiple Unspecified Vulnerabilities");
  script_summary(english:"Checks version of Adobe Reader");

 script_set_attribute(attribute:"synopsis", value:
"The PDF file viewer on the remote Windows host is affected by several issues." );
 script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is earlier than 7.0.8
and thus reportedly is affected by several security issues. While details on
the nature of these flaws is currently unknown, the vendor ranks them low,
saying they have minimal impact and are difficult to exploit." );
 # http://web.archive.org/web/20060618175415/http://www.adobe.com/support/techdocs/327817.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c51296a5" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 7.0.8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/11");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/06/08");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
  if (ver =~ "^([0-6]\.|7\.0\.[0-7][^0-9.]?)")
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
  security_warning(port:get_kb_item("SMB/transport"), extra:report);
}
else security_warning(get_kb_item("SMB/transport"));
