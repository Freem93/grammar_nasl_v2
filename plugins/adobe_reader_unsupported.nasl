#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56213);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/01/18 17:44:08 $");

  script_name(english:"Adobe Reader Unsupported Version Detection");
  script_summary(english:"Checks the Adobe Reader version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Adobe Reader.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installation of Adobe
Reader on the remote Windows host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  #http://prodesigntools.com/adobe-acrobat-dc-document-cloud.html 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d63c933d");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/programs/policies/supported.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Adobe Reader that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


versions = get_kb_list('SMB/Acroread/Version');
if (isnull(versions)) exit(0, 'The "SMB/Acroread/Version" KB list is missing.');

eos_dates = make_array(
  '10', 'November 18, 2015',
  '9', 'June 26, 2013',
  '8', 'November 3, 2011',
  '7', '',
  '6', '',
  '5', '',
  '4', '',
  '3', '',
  '2', '',
  '1', ''
);
withdrawl_announcements = make_array(
  '10', 'https://blogs.adobe.com/documentcloud/adobe-acrobat-x-and-adobe-reader-x-end-of-support/',
  '9', 'https://helpx.adobe.com/acrobat/kb/end-support-acrobat-8-reader.html', #Actual content is for 9
  '8', 'http://blogs.adobe.com/adobereader/2011/09/adobe-reader-and-acrobat-version-8-end-of-support.html'
);
supported_versions = '11.x / 2015';


info = "";
info2 = "";

foreach version (versions)
{
  path   = get_kb_item("SMB/Acroread/"+version+"/Path");
  report_version = get_kb_item("SMB/Acroread/"+version+"/Version_UI");
  if (isnull(report_version))
    report_version = version;

  ver = split(version, sep:".", keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);
  version_highlevel = ver[0];

  foreach v (keys(eos_dates))
  {
    if (v == version_highlevel)
    {
      register_unsupported_product(product_name:"Adobe Acrobat Reader", version:report_version, cpe_base:"adobe:acrobat_reader");

      info +=
        '\n  Path                : ' + path +
        '\n  Installed version   : ' + report_version;
      if (eos_dates[version_highlevel])
        info += '\n  End of support date : ' + eos_dates[version_highlevel];
      if (withdrawl_announcements[version_highlevel])
        info += '\n  Announcement        : ' + withdrawl_announcements[version_highlevel];
      info += '\n  Supported versions  : ' + supported_versions + '\n';
      break;
    }
  }
  info2 += " and " + report_version;
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);

  exit(0);
}

if (info2)
{
 info2 -= " and ";
  if (" and " >< info2) be = "are";
  else be = "is";

  exit(0, "The host is not affected since Adobe Reader " + info2 + " " + be + " installed.");
}
else exit(1, "Unexpected error - 'info2' is empty.");
