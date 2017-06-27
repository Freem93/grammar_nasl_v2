#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70350);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/01/18 17:44:08 $");

  script_name(english:"Adobe Acrobat Unsupported Version Detection (Mac OS X)");
  script_summary(english:"Checks the Adobe Acrobat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Adobe Acrobat.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installation of Adobe
Acrobat on the remote Mac OS X host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # http://prodesigntools.com/adobe-acrobat-dc-document-cloud.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d63c933d");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/programs/policies/supported.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Adobe Acrobat that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_acrobat_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Adobe_Acrobat/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_HOST_NOT, "Mac OS X");


kb_base = "MacOSX/Adobe_Acrobat";
get_kb_item_or_exit(kb_base+"/Installed");

versions = get_kb_list(kb_base+"/*/Version");
if (isnull(versions)) audit(AUDIT_KB_MISSING, kb_base+'/*/Version');

eos_dates = make_array(
  '10', 'November 15, 2015',
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

foreach install (sort(keys(versions)))
{
  path = "/Applications" + (install - kb_base - "/Version");

  version = versions[install];

  ver = split(version, sep:".", keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);
  version_highlevel = ver[0];

  foreach v (keys(eos_dates))
  {
    if (v == version_highlevel)
    {
      register_unsupported_product(product_name:'Adobe Acrobat',
                                   version:version, cpe_base:"adobe:acrobat");
      info +=
        '\n  Path                : ' + path +
        '\n  Installed version   : ' + version;
      if (eos_dates[version_highlevel])
        info += '\n  End of support date : ' + eos_dates[version_highlevel];
      if (withdrawl_announcements[version_highlevel])
        info += '\n  Announcement        : ' + withdrawl_announcements[version_highlevel];
      info += '\n  Supported versions  : ' + supported_versions + '\n';
      break;
    }
  }
  info2 += " and " + version;
}

if (info)
{
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}

if (info2)
{
 info2 -= " and ";
  if (" and " >< info2) be = "are";
  else be = "is";

  audit(AUDIT_INST_VER_NOT_VULN, "Adobe Acrobat", info2);
}
else exit(1, "Unexpected error - 'info2' is empty.");
