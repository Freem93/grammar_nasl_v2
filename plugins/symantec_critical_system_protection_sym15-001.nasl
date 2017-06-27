#
# (C) Tenable Network Security, Inc,
#

include("compat.inc");

if (description)
{
  script_id(80911);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/08/24 15:27:28 $");

  script_cve_id(
    "CVE-2014-3440",
    "CVE-2014-7289",
    "CVE-2014-9224",
    "CVE-2014-9225",
    "CVE-2014-9226",
    "CVE-2015-8157",
    "CVE-2015-8798",
    "CVE-2015-8799",
    "CVE-2015-8800"
  );
  script_bugtraq_id(
    72091,
    72092,
    72093,
    72094,
    72095,
    90884,
    90885,
    90886,
    90889 
  );
  script_osvdb_id(
    117355,
    117356,
    117357,
    117358,
    117359,
    117515,
    139527,
    139528,
    139529,
    139530
  );
  script_xref(name:"EDB-ID", value:"35915");
  script_xref(name:"IAVA", value:"2016-A-0211");

  script_name(english:"Symantec Critical System Protection 5.2.9.x < 5.2.9 MP6 Multiple Vulnerabilities (SYM15-001 / SYM16-009)");
  script_summary(english:"Checks the version of Symantec Critical System Protection.");

  script_set_attribute(attribute:"synopsis", value:
"The remote windows host has a security application installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Critical System Protection (SCSP) installed on
the remote Windows host is 5.2.9.x prior to 5.2.9 MP6. It is,
therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the
    Management Server Agent Control Interface due to
    improper sanitization of user-uploaded files. An
    authenticated, remote attacker can exploit this, by
    uploading a log file, to execute arbitrary script code
    with the privileges of the web server. (CVE-2014-3440)

  - A SQL injection (SQLi) vulnerability exists in the
    management server due to the /sis-ui/authenticate script
    not properly sanitizing user-supplied input to the 'ai'
    POST parameter. An unauthenticated, remote attacker can
    exploit this to inject or manipulate SQL queries in the
    back-end database, resulting in the manipulation or
    disclosure of arbitrary data. (CVE-2014-7289)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist in the management server in the
    WCUnsupportedClass.jsp script and SSO-Error.jsp script
    due to improper validation of user-supplied input to the
    'classname' and 'ErrorMsg' GET parameters. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary script code in a user's browser
    session. (CVE-2014-9224)

  - An information disclosure vulnerability exists in the
    management server due to a failure to properly restrict
    internal server information. An authenticated, remote
    attacker can exploit this, via a direct request to the
    environment.jsp script, to disclose sensitive server
    information. (CVE-2014-9225)

  - A privilege escalation vulnerability exists due to a
    failure to sufficiently restrict access to certain host
    functionality. A local attacker can exploit this to
    bypass protection policies and gain elevated privileges.
    (CVE-2014-9226)

  - A SQL injection (SQLi) vulnerability exists in the
    management server due to improper sanitization of
    user-supplied input. An authenticated, remote attacker
    can exploit this to inject or manipulate SQL queries in
    the back-end database, resulting in the manipulation or
    disclosure of arbitrary data. (CVE-2015-8157)

  - A path traversal issue exists due to improper
    sanitization of user-supplied input. An authenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary code.
    (CVE-2015-8798)

  - A path traversal issue exists that allows an
    authenticated, remote attacker to write update-package
    data to arbitrary agent locations, resulting in the
    execution of arbitrary code. (CVE-2015-8799)

  - An unspecified flaw exists that is triggered when
    handling process calls written to a specific named pipe.
    An authenticated, remote attacker can exploit this to
    inject arbitrary arguments. (CVE-2015-8800)");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20150119_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f75a756a");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160607_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73704eaf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Critical System Protection 5.2.9 MP6 or later.
Alternatively, apply the workarounds referenced in the vendor
advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:critical_system_protection");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_critical_system_protection_installed.nbin");
  script_require_keys("installed_sw/Symantec Critical System Protection");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

appname = "Symantec Critical System Protection";

install = get_single_install(app_name:appname);

version = install['version'];
path = install['path'];
build = install['Build'];

if (version =~ '^5\\.2\\.9$' && ver_compare(ver:build, fix:'905', strict:FALSE) <= 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
  set_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.2.9 MP6' +
      '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
