#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62010);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id(
    "CVE-2012-0307",
    "CVE-2012-0308",
    "CVE-2012-3579",
    "CVE-2012-3580",
    "CVE-2012-3581",
    "CVE-2012-4347"
  );
  script_bugtraq_id(55137, 55138, 55141, 55142, 55143, 56789);
  script_osvdb_id(84897, 85026, 85027, 85028, 85029, 88165);
  script_xref(name:"EDB-ID", value:"21136");
  script_xref(name:"EDB-ID", value:"23109");
  script_xref(name:"EDB-ID", value:"23110");

  script_name(english:"Symantec Messaging Gateway 9.5.x Multiple Vulnerabilities (SYM12-013)");
  script_summary(english:"Checks SMG version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A messaging security application running on the remote host has
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of Symantec
Messaging Gateway running on the remote host is 9.5.x and has the
following vulnerabilities :

  - Multiple XSS vulnerabilities exist. (CVE-2012-0307)

  - Lack of password protection on sensitive functions as
    well as of CSRF protection could be abused through CSRF
    attacks, for example, to add a backdoor administrator
    account. (CVE-2012-0308)

  - The 'support' account with SSH access is secured with
    the password 'symantec'. (CVE-2012-3579)

  - An unspecified web application modification issue 
    exists. (CVE-2012-3580)

  - An unspecified flaw may allow a remote attacker to gain
    access to potentially sensitive component version 
    information. (CVE-2012-3581)

  - An authenticated user is able to download arbitrary
    files with the permissions of the Webserver user using
    specially crafted GET requests, such as using the
    'logFile' parameter of 'brightmail/export', the
    'localBackupFileSelection' parameter of
    'brightmail/admin/restore/download.do', and possibly
    others. (CVE-2012-4347)"
  );
  # https://www.sec-consult.com/files/20120828-0_Symantec_Mail_Gateway_Support_Backdoor_v04.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97079438");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524191/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524192/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524193/30/0/threaded");

  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524876/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524877/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524878/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524879/30/0/threaded");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120827_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e796fd4d");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Symantec Messaging Gateway 10.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Symantec Messaging Gateway 9.5.3 File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Symantec Messaging Gateway 9.5 Default SSH Password Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:messaging_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_messaging_gateway_detect.nasl");
  script_require_keys("www/sym_msg_gateway");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);
install = get_install_from_kb(appname:'sym_msg_gateway', port:port, exit_on_fail:TRUE);
base_url = build_url(qs:install['dir'], port:port);

if (install['ver'] == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Symantec Messaging Gateway', base_url);
if (install['ver'] !~ "^9\.5(\.|$)")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Messaging Gateway', base_url, install['ver']);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + base_url +
    '\n  Installed version : ' + install['ver'] +
    '\n  Fixed version     : 10.0\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
