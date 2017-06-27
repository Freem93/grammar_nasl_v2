#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78676);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_osvdb_id(113251);
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20141015-poodle");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur27617");

  script_name(english:"Cisco AnyConnect Secure Mobility Client < 3.1(5187) (POODLE)");
  script_summary(english:"Checks the version of the Cisco AnyConnect client.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Cisco AnyConnect prior to 3.1(5187).
It is, therefore, affected by an information disclosure vulnerability
known as POODLE. The vulnerability is due to the way SSL 3.0 handles
padding bytes when decrypting messages encrypted using block ciphers
in cipher block chaining (CBC) mode. A MitM attacker can decrypt a
selected byte of a cipher text in as few as 256 tries if they are able
to force a victim application to repeatedly send the same data over
newly created SSL 3.0 connections.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141015-poodle
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7453d3be");
  # MS workaround
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/3009008.aspx");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20141015.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client 3.1(5187) or later.

Alternatively, apply the workaround provided by Microsoft.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl", "smb_kb3009008.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# If not paranoid, need to know if workaround is enabled.
# smb_kb3009008.nasl checks for the suggested workaround.
if (report_paranoia < 2)
{
  workaround_enabled = get_kb_item("SMB/ssl_v3_poodle_workaround_enabled");
  if (workaround_enabled) exit(0, "SSLv3 has been disabled in Windows.");
}

appname = "Cisco AnyConnect Secure Mobility Client";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install['path'];
ver  = install['version'];

fix = '3.1.5187';
fix_display = fix + ' (3.1(5187))';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix_display +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
