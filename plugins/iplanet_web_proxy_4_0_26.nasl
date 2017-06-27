#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84962);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/24 14:57:04 $");

  script_cve_id("CVE-2014-1569");
  script_bugtraq_id(71675);
  script_osvdb_id(115397);

  script_name(english:"Oracle iPlanet Web Proxy Server 4.0.x < 4.0.26 NSS Signature Handling Remote Code Injection");
  script_summary(english:"Checks the proxyd.exe product version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy web server is affected by a remote code injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle iPlanet Web Proxy
Server (formerly known as Sun Java System Web Proxy Server) installed 
on the remote host is version 4.0.x prior to 4.0.26. It is, therefore, 
affected by a flaw in the definite_length_decoder() function in the 
Network Security Services (NSS) library due to a failure to ensure 
that the DER encoding of an ASN.1 length is properly formed when 
handling PKCS#1 signatures. A remote attacker, by using a long byte 
sequence for an encoding, can exploit this to conduct a data-smuggling
attack or inject arbitrary code.");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18c2a85");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/09/26/pkcs1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle iPlanet Web Proxy Server 4.0.26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:iplanet_web_proxy_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:network_security_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("iplanet_web_proxy_installed.nbin");
  script_require_keys("installed_sw/Oracle iPlanet Web Proxy Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = 'Oracle iPlanet Web Proxy Server';

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

fixed_version = '4.0.26';
min_version   = '4.0';

if (
  ver_compare(ver:version, fix:min_version, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version;

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
