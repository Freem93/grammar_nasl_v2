#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71465);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2011-2040", "CVE-2013-5559");
  script_bugtraq_id(48081, 63491);
  script_osvdb_id(72715, 99258);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsy05934");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj58139");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110601-ac");
  script_xref(name:"CERT", value:"490097");

  script_name(english:"Mac OS X : Cisco AnyConnect Secure Mobility Client 2.x / 3.x < 3.0(629) Multiple Vulnerabilities");
  script_summary(english:"Checks version of Cisco AnyConnect Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Cisco AnyConnect 2.x or 3.x prior to
3.0(629) and is, therefore, affected by the following vulnerabilities :

  - When the client is obtained from the VPN headend using
    a web browser, a helper application performs the
    download and installation.  This helper application does
    not verify the authenticity of the downloaded installer,
    which could allow an attacker to send malicious code to
    the user instead. Note 2.x versions prior to 2.5.3041
    are affected by this vulnerability. (CVE-2011-2040)

  - When the VPNAPI COM module calls the ATL framework,
    certain input data are not properly validated. This
    could allow a buffer overflow, which could lead to
    arbitrary code execution. (CVE-2013-5559)"
  );
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCsy05934");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuj58139");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20110601-ac.html");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=23243");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31606");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client 3.0(629) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_cisco_anyconnect_installed.nasl");
  script_require_keys("MacOSX/Cisco_AnyConnect/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = 'Cisco AnyConnect Mobility VPN Client';

kb_base = "MacOSX/Cisco_AnyConnect";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

fix = '3.0.629.0';
fix_display = fix + ' (3.0(629))';

if ((version =~ "^2\." || version =~ "^3\.0\.") && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix_display + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
