#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80861);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/21 15:40:55 $");

  script_cve_id("CVE-2014-3314");
  script_bugtraq_id(72059);
  script_osvdb_id(117016);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo24931");

  script_name(english:"Mac OS X : Cisco AnyConnect Secure Mobility Client < 3.1(6042) Host Validation Vulnerability");
  script_summary(english:"Checks the version of the Cisco AnyConnect client.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a host validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Cisco AnyConnect Secure
Mobility Client prior to 3.1(6042). It is, therefore, affected by a
vulnerability due to insufficient validation of the type of host which
the client is connecting to. An attacker, by tricking users to connect
to a malicious host, can exploit this to force the client to render a
crafted authentication form to collect valid credentials.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3314
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b96636d");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuo24931");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco AnyConnect Secure Mobility Client 3.1(6042) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("macosx_cisco_anyconnect_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "Host/MacOSX/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Exit unless we're paranoid because we can't detect if the workaround
# has been applied.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("Host/MacOSX/Version");

appname = "Cisco AnyConnect Secure Mobility Client";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install['path'];
ver  = install['version'];

fix = '3.1.6042';
fix_display = fix + ' (3.1(6042))';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix_display +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
