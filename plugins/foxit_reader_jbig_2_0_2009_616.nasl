#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39481);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2009-0690", "CVE-2009-0691");
  script_bugtraq_id(35442, 35443);
  script_osvdb_id(55618, 55619);
  script_xref(name:"CERT", value:"251793");

  script_name(english:"Foxit Reader JPEG2000 / JBIG Decoder Add-On < 2.0.2009.616 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Foxit Reader application installed on the remote Windows host
includes an optional JPEG2000 / JBIG Decoder add-on that is prior to
version 2.0.2009.616. It is, therefore affected by multiple
vulnerabilities :

  - A out-of-bounds read error exists in the add-on due to
    improper handling of a negative value for the stream
    offset in a JPEG2000 (JPX) stream. An unauthenticated,
    remote attacker can exploit this, via a crafted PDF
    file, to cause a denial of service or to execute
    arbitrary code. (CVE-2009-0690)

  - A flaw exists in the add-on due to improper handling of
    an unspecified fatal error during the decoding of a
    JPEG2000 (JPX) header. An unauthenticated, remote
    attacker can exploit this, via a crafted PDF file, to
    cause a denial of service or to execute arbitrary code.
    (CVE-2009-0691)");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/company/press.php?id=124");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 3.0 Build 1817 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");

app = "Foxit Reader";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
path = install['path'];

file = "fxdecod1.dll";
fixed_version = "2.0.2009.616";

# some versions are flat, some store in the 'plugins' directory.
paths = make_list("", "plugins");
ver = NULL;

foreach plugin_path (paths)
{
  cur_path = path + "\" + plugin_path;
  version = hotfix_get_fversion(path:cur_path + "\" + file );
  if (version['error'] == HCF_OK)
  {
    ver = join(version['value'], sep:'.');
    path = cur_path;
    break;

  }
  else
    continue;
}

hotfix_check_fversion_end();

report = NULL;
if (ver)
{
  if (ver_compare(ver:ver, fix:fixed_version, strict:FALSE) < 0)
  {
  port = kb_smb_transport();

  report =
    '\n  Plugin path (fxdecod1.dll) : ' + path +
    '\n  Plugin version             : ' + ver +
    '\n  Fixed version              : ' + fixed_version +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
  }
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, path);
