#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86698);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_bugtraq_id(76130, 76132, 76391);
  script_osvdb_id(125418, 126400, 126401);
  script_xref(name:"EDB-ID", value:"37699");
  script_xref(name:"ZDI", value:"ZDI-15-393");
  script_xref(name:"ZDI", value:"ZDI-15-395");

  script_name(english:"Foxit Reader < 7.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"The version of Foxit Reader installed on the remote Windows host is
prior to 7.2. It is, therefore, affected by multiple vulnerabilities :

  - A memory overflow condition exists in the PDF creator
    plugin (ConvertToPDF_x86.dll) when converting a PNG file
    to a PDF file due to an error that occurs when copying a
    memory block. An attacker can exploit this to execute
    arbitrary code. (BID 76130)

  - A memory corruption issue exists when opening certain
    XFA forms. An attacker can exploit this to generate
    files that crash the application. (BID 76132)

  - A flaw exists in the PDF creaStor plugin
    (ConvertToPDF_x86.dll) that is triggered when handling
    'tEXt' chunks in PNG images. An attacker can exploit
    this to execute arbitrary code. (VulnDB 125418)

  - A heap corruption issue exists when processing malformed
    color table data in a GIF file. An unauthenticated,
    remote attacker can exploit this, via a crafted GIF
    file, to execute arbitrary code. (VulnDB 126400)

  - A flaw exists when converting a TIFF file to a PDF file
    due to reading a VTABLE from an invalid location. An
    unauthenticated, remote attacker can exploit this, via
    a crafted TIFF image, to execute arbitrary code.
    (VulnDB 126401)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-393/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-395/");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 7.2.0.722 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Foxit Reader";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install["version"];
path    = install["path"];

report = NULL;

fixed_version = "7.2.0.0722";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port)
    port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version + '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

