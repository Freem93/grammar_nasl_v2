#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73668);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/20 14:21:43 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"OpenVPN 2.3.x Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks OpenVPN version");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of OpenVPN
installed on the remote host is affected by an out-of-bounds read
error, known as the 'Heartbleed Bug' in the included OpenSSL version.

This error is related to handling TLS heartbeat extensions that could
allow an attacker to obtain sensitive information such as primary key
material, secondary key material, and other protected content. Note
this affects both client and server modes of operation.");
  script_set_attribute(attribute:"see_also", value:"https://community.openvpn.net/openvpn/wiki/heartbleed");
  script_set_attribute(attribute:"see_also", value:"https://community.openvpn.net/openvpn/wiki/ChangesInOpenvpn23");
  script_set_attribute(attribute:"see_also", value:"http://heartbleed.com/");
  script_set_attribute(attribute:"see_also", value:"http://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 2.3.4 (Installer I001) / 2.3.3 (Installer I002) / 2.3.2
(Installer I004) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvpn:openvpn");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("openvpn_installed.nbin");
  script_require_keys("SMB/OpenVPN/Installed");
  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/OpenVPN/Installed");
installs = get_kb_list_or_exit("SMB/OpenVPN/*/Version");
kb_entry = branch(keys(installs));
kb_base = kb_entry - "/Version";

version = get_kb_item_or_exit(kb_entry);
path    = get_kb_item_or_exit(kb_base + "/Path");

if (version =~ "^2(\.3)?$") audit(AUDIT_VER_NOT_GRANULAR, "OpenVPN", version);
if (version !~ "^2\.3[^0-9]") audit(AUDIT_NOT_INST, "OpenVPN 2.3.x");

# Note : vendor has been rebuilding the
# same versions with different versions of
# openssl, so we need to check openssl dll.
# OpenSSL 1.0.1 through 1.0.1f are vuln.
openssl_ver  = get_kb_item_or_exit(kb_base + "/ssleay32_dll_version");
openssl_path = get_kb_item_or_exit(kb_base + "/ssleay32_dll_path");

if (openssl_ver =~ "^1\.0\.1($|[a-f])")
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    # Set user-friendly report ver if possible
    if (version =~ "^2\.3\.4($|[^0-9])") fixed_version = '2.3.4 (Installer I001)';
    else if (version =~ "^2\.3\.3($|[^0-9])") fixed_version = '2.3.3 (Installer I002)';
    else if (version =~ "^2\.3\.2($|[^0-9])") fixed_version = '2.3.2 (Installer I004)';
    else fixed_version = '2.3.4 (Installer I001) / 2.3.3 (Installer I002) / 2.3.2 (Installer I004)';

    report = '\n  OpenVPN path              : ' + path +
             '\n  OpenVPN installed version : ' + version +
             '\n  Fixed version             : ' + fixed_version +
             '\n  DLL file                  : ' + openssl_path +
             '\n  DLL installed version     : ' + openssl_ver +
             '\n  DLL fixed version         : 1.0.1g';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "OpenVPN", version, path);
