#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73896);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2014-0076", "CVE-2014-0160");
  script_bugtraq_id(66363, 66690);
  script_osvdb_id(104810, 105465);
  script_xref(name:"VMSA", value:"2014-0004");
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"VMware Horizon Workspace 1.8 < 1.8.1 OpenSSL Library Multiple Vulnerabilities (VMSA-2014-0004) (Heartbleed)");
  script_summary(english:"Checks version of VMware Horizon Workspace");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a device management application installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Horizon Workspace installed on the remote host
is version 1.8.x prior to 1.8.1. It is, therefore, reportedly affected
by the following vulnerabilities in the OpenSSL library :

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - An out-of-bounds read error, known as the 'Heartbleed
    Bug', exists related to handling TLS hearbeat
    extensions that could allow an attacker to obtain
    sensitive information such as primary key material,
    secondary key material and other protected content.
    (CVE-2014-0160)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0004");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2076225");
  # https://www.vmware.com/support/ws10/doc/workstation-1002-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a48b929");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");

  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Horizon Workspace 1.8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/06");

  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:vmware_horizon_workspace");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_horizon_workspace_detect.nbin");
  script_require_keys("www/vmware_horizon_workspace");
  script_require_ports("Services/www", 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = 'VMware Horizon Workspace';

port = get_http_port(default:8443);

install = get_install_from_kb(appname:'vmware_horizon_workspace', port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_loc = build_url(port:port, qs:dir + '/');
version = install['ver'];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_loc);
if (version !~ '^1\\.8(\\.| )') exit(0, 'The VMware Horizon Workspace install at ' + install_loc + ' is not version 1.8.x.');

matches = eregmatch(pattern:'^([0-9\\.]+) Build ([0-9]+)$', string:version);
if (matches)
{
  ver = split(matches[1], sep:'.', keep:FALSE);
  if (max_index(ver) < 3) audit(AUDIT_VER_NOT_GRANULAR, app, version);
  for (i=0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);
  build = int(matches[2]);
}
else audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_loc);

if (ver[0] == 1 && ver[1] == 8 && (ver[2] < 1 || (ver[2] == 1 && build < 1752537)))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_loc +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.8.1 Build 1752537\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
}
