#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(67122);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/07/02 14:08:03 $");

  script_cve_id("CVE-2013-0732");
  script_bugtraq_id(60315);
  script_osvdb_id(93870);

  script_name(english:"Nuance PDF Reader pdfcore8.dll Heap Buffer Overflow");
  script_summary(english:"Checks version of Nuance PDF Reader");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
heap-based buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Nuance PDF Reader installed on the remote host is prior
to 8.1.  As such, it is affected by a heap-based buffer overflow
vulnerability.  The vulnerability exists in the 'PDFCore8.dll' when
allocating memory for a font table directory during the handling of
naming tables when handling TTF files. 

An attacker could exploit this issue by tricking a user into opening a
specially crafted document, resulting in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.nuance.com/products/pdf-reader/index.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade to Nuance PDF Reader 8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nuance:pdf_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("nuance_pdf_reader_detect.nasl");
  script_require_keys("SMB/Nuance_PDF_Reader/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

appname = "Nuance PDF Reader";
kb_base = "SMB/Nuance_PDF_Reader/";
path = get_kb_item_or_exit(kb_base + "Path");
ver = get_kb_item_or_exit(kb_base + "Version");

fix = "8.1";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix +
        '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
