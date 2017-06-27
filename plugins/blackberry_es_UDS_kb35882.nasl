#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73762);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/19 17:45:33 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"BlackBerry Enterprise Service Information Disclosure (KB35882) (Heartbleed)");
  script_summary(english:"Checks version of UDS tcnative-1.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The BlackBerry Enterprise Service (BES) install on the remote host is
affected by an out-of-bounds read error, known as the 'Heartbleed Bug'
in the included OpenSSL version.

This error is related to handling TLS heartbeat extensions that could
allow an attacker to obtain sensitive information such as primary key
material, secondary key material, and other protected content. Note
this affects both client and server modes of operation.");
  script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/KB35882");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:"Apply the patch referred to in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:blackberry:blackberry_enterprise_service");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl");
  script_require_keys("BlackBerry_ES/Product");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

product = get_kb_item_or_exit("BlackBerry_ES/Product");
version = get_kb_item_or_exit("BlackBerry_ES/Version");
path = get_kb_item_or_exit("BlackBerry_ES/Path");

app_name = "BlackBerry Enterprise Service";

if ("BlackBerry Enterprise Service" >!< product) audit(AUDIT_NOT_INST, app_name);

if (version !~ "^10\.[12]\.") audit(AUDIT_NOT_INST, app_name+" 10.x");

# Now, go check fileversion of tcnative-1.dll for UDS.
# Note that, other tcnative-1.dll files may exist on
# the server, this check is for the instance related
# to UDS.
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

registry_init();

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

info = "";
dll = "\RIM.BUDS.BWCN\bin\tcnative-1.dll";
temp_path = path + dll;
dll_ver = hotfix_get_fversion(path:temp_path);
err_res = hotfix_handle_error(
  error_code   : dll_ver['error'],
  file         : temp_path,
  appname      : app_name,
  exit_on_fail : TRUE
);
hotfix_check_fversion_end();

dll_version = join(dll_ver['value'], sep:".");

# TC-Native begins using OpenSSL 1.0.1 branch (vuln) at version 1.1.24.0
# TC-Native begins using OpenSSL 1.0.1g (patched) at version 1.1.30.0
if (
  ver_compare(ver:dll_version, fix:'1.1.24.0', strict:FALSE) >= 0 &&
  ver_compare(ver:dll_version, fix:'1.1.30.0', strict:FALSE) < 0
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + product +
      '\n  Path              : ' + temp_path +
      '\n  Installed version : ' + dll_version +
      '\n  Fixed version     : 1.1.30.0' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
