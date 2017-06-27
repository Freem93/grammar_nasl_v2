#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72035);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/07/17 00:03:37 $");

  script_cve_id("CVE-2013-5808");
  script_bugtraq_id(64827);
  script_osvdb_id(102029);

  script_name(english:"Oracle iPlanet Web Proxy Server 4.0 < 4.0.23 Unspecified Vulnerability");
  script_summary(english:"Checks proxyd.exe's product version.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web proxy server on the remote host is affected by an unspecified
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Oracle iPlanet Web Proxy Server
(formerly Sun Java System Web Proxy Server) 4.0 prior to 4.0.23. It
is, therefore, affected by an unspecified vulnerability related to
Administration."
  );
  # http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17c46362");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 4.0.23 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:iplanet_web_proxy_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("iplanet_web_proxy_installed.nbin");
  script_require_keys("SMB/iplanet_web_proxy_server/path", "SMB/iplanet_web_proxy_server/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = 'Oracle iPlanet Web Proxy Server';
version = get_kb_item_or_exit('SMB/iplanet_web_proxy_server/version');
path = get_kb_item_or_exit('SMB/iplanet_web_proxy_server/path');

fixed_version = '4.0.23';
min_version = '4.0';

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

    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
