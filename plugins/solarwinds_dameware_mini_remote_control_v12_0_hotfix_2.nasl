#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86995);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/11/23 14:38:53 $");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_osvdb_id(113251);
  script_xref(name:"CERT", value:"577193");

  script_name(english:"SolarWinds DameWare Mini Remote Control < 12.0 Hotfix 2 SSLv3 Padding Oracle On Downgraded Legacy Encryption (POODLE)");
  script_summary(english:"Checks the version of DameWare Mini Remote Control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a remote management application that is
affected by a man-in-the-middle (MitM) information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of SolarWinds DameWare Mini
Remote Control prior to 12.0 Hotfix 2. It is, therefore, affected by
a man-in-the-middle (MitM) information disclosure vulnerability known
as POODLE. The vulnerability is due to the way SSL 3.0 handles padding
bytes when decrypting messages encrypted using block ciphers in cipher
block chaining (CBC) mode. A MitM attacker can decrypt a selected byte
of a cipher text in as few as 256 tries if they are able to force a
victim application to repeatedly send the same data over newly created
SSL 3.0 connections.");
  script_set_attribute(attribute:"see_also", value:"https://thwack.solarwinds.com/message/313220#313220");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds DameWare Mini Remote Control v12.0 Hotfix 2 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:solarwinds:dameware_mini_remote_control");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("solarwinds_dameware_mini_remote_control_installed.nbin");
  script_require_keys("installed_sw/SolarWinds DameWare Mini Remote Control");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "SolarWinds DameWare Mini Remote Control";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
path = install['path'];
version = install['version'];
fix = "12.0.0.520";

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
