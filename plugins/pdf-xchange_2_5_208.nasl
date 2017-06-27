#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65549);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/14 17:25:02 $");

  script_cve_id("CVE-2013-0729");
  script_bugtraq_id(57491);
  script_osvdb_id(89442);

  script_name(english:"PDF-XChange Viewer < 2.5 Build 208 JPEG Processing Buffer Overflow");
  script_summary(english:"Checks for vulnerable versions of PDF-XChange Viewer software.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a buffer
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"A version of PDF-XChange Viewer prior to 2.5 Build 208 is installed on
the remote host.  As such, it contains a flaw in the JPEG stream parsing
feature that is triggered when the Define Huffman Table header of a JPEG
image is not properly validated when embedded in a PDF document.  An
attacker could exploit this issue by tricking a user into opening a
malicious PDF document, resulting in denial of service or arbitrary code
execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.tracker-software.com/company/news_press_events/view/123");
  script_set_attribute(attribute:"solution", value:"Upgrade to PDF-XChange Viewer 2.5 Build 208 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tracker-software:pdf-xchange");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tracker-software:pdf-xchange:viewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2003 -2013 Tenable Network Security, Inc.");

  script_dependencies("pdf-xchange_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Tracker_Software/PDF-XChange Viewer/Installed");
  script_require_ports(139,445);
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");

appname = "PDF-XChange Viewer";
fixed = '2.5.208';

kb_base = "SMB/Tracker_Software/PDF-XChange Viewer/";
installs = get_kb_list_or_exit(kb_base + "*");

info = '';
report = '';
foreach install (keys(installs))
{
  if ("/Installed" >< install) continue;

  matches = eregmatch(pattern:"^SMB/Tracker_Software/PDF-XChange Viewer/([0-9.]+)$", string:install);
  if (matches)
  {
    version = matches[1];
    ver = split(version, sep:".", keep:FALSE);
    version_ui = ver[0] + '.' + ver[1] + " Build " + ver[2];

    path = get_kb_item_or_exit(kb_base + version);

    if (ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
    {
      report += '\n' +
         '\n  Path              : ' + path +
         '\n  Installed version : ' + version_ui +
         '\n  Fixed version     : 2.5 Build 208' +
         '\n';
    }
    else
    {
      info += '\n' + appname + " version " + version_ui + ", under " + path + " ";
    }
  }
}
if (!report)
{
  if (info != '') exit(0, "The following instance(s) of PDF-XChange Viewer are installed but not vulnerable : "+ info);
  else exit(1, "An unknown error occurred.");
}

port = kb_smb_transport();
if (report_verbosity > 0) security_hole(port:port, extra:report);
else security_hole(port);
