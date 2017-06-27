#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86697);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_bugtraq_id(76130, 76132, 76391);
  script_osvdb_id(126400, 126401);

  script_name(english:"Foxit PhantomPDF < 7.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit PhantomPDF.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"According to its version, the Foxit PhantomPDF application (formally
known as Phantom) installed on the remote Windows host is affected by
multiple vulnerabilities :

  - A memory overflow condition exists in the PDF creator
    plugin (ConvertToPDF_x86.dll) when converting a PNG file
    to a PDF file due to an error that occurs when copying a
    memory block. An attacker can exploit this to execute
    arbitrary code. (BID 76130)

  - A memory corruption issue exists when opening certain
    XFA forms. An attacker can exploit this to generate
    files that crash the application. (BID 76132)

  - A heap corruption issue exists when processing malformed
    color table data in a GIF file. An unauthenticated,
    remote attacker can exploit this by using a crafted GIF
    file to execute arbitrary code. (VulnDB 126400)

  - A flaw exists when converting a TIFF file to a PDF file
    due to reading a VTABLE from an invalid location. An
    unauthenticated, remote attacker can exploit this by
    using a crafted TIFF image to execute arbitrary code.
    (VulnDB 126401)");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security_bulletins.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 7.2.0722 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

fixed_version = "7.2.0.722";
appname = "FoxitPhantomPDF";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install["path"];
version = install["version"];
name = install["Application Name"];
port = get_kb_item("SMB/transport");
if (!port)
  port = 445;

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  security_report_v4(port:port, extra:
    '\n  Application Name  : ' + name +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version,
    severity:SECURITY_HOLE);
}
else
{
  audit(AUDIT_INST_VER_NOT_VULN, name, version);
}
exit(0);
