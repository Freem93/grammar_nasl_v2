#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95812);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/16 14:23:20 $");

  script_cve_id(
    "CVE-2016-8016",
    "CVE-2016-8017",
    "CVE-2016-8018",
    "CVE-2016-8019",
    "CVE-2016-8020",
    "CVE-2016-8021",
    "CVE-2016-8022",
    "CVE-2016-8023",
    "CVE-2016-8024",
    "CVE-2016-8025"
  );
  script_bugtraq_id(94823);
  script_osvdb_id(
    148538,
    148539,
    148540,
    148541,
    148542,
    148543,
    148544,
    148545,
    148546,
    148547
  );
  script_xref(name:"MCAFEE-SB", value:"SB10181");
  script_xref(name:"CERT", value:"245327");
  script_xref(name:"EDB-ID", value:"40911");

  script_name(english:"McAfee VirusScan Enterprise for Linux <= 2.0.3 Multiple vulnerabilities (SB10181)");
  script_summary(english:"Checks VSEL version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee VirusScan Enterprise for Linux
(VSEL) installed that is prior or equal to 2.0.3. It is, therefore,
affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    web interface due to improper error reporting. An
    authenticated, remote attacker can exploit this, by
    manipulating the 'tplt' parameter, to disclose filenames
    on the system. (CVE-2016-8016)

  - An information disclosure vulnerability exists in the
    parser due to improper handling of template files. An
    authenticated, remote attacker can exploit this, via
    specially crafted text elements, to disclose the
    contents of arbitrary files subject to the privileges of
    the 'nails' account. (CVE-2016-8017)

  - Multiple cross-site request forgery (XSRF)
    vulnerabilities exist in the web interface due to a
    failure to require multiple steps, explicit
    confirmation, or a unique token when performing certain
    sensitive actions. An unauthenticated, remote attacker
    can exploit these vulnerabilities, by convincing a user
    to follow a specially crafted link, to execute arbitrary
    script code or commands in a user's browser session.
    (CVE-2016-8018)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist due to improper validation of user-supplied input
    to the 'info:7' and 'info:5' parameters when the 'tplt'
    parameter is set in NailsConfig.html or
    MonitorHost.html. An unauthenticated, remote attacker
    can exploit these vulnerabilities, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2016-8019)

  - A remote code execution vulnerability exists due to
    improper validation of user-supplied input to the
    'nailsd.profile.ODS_9.scannerPath' variable in the last
    page of the system scan form. An authenticated, remote
    attacker can exploit this, via a specially crafted HTTP
    request, to execute arbitrary code as the root user.
    (CVE-2016-8020)

  - A remote code execution vulnerability exists in the web
    interface when downloading update files from a specified
    update server due to a race condition. An authenticated,
    remote attacker can exploit this to place and execute a
    downloaded file before integrity checks are completed.
    (CVE-2016-8021)

  - A security bypass vulnerability exists in the web
    interface due to improper handling of authentication
    cookies. The authentication cookie stores the IP address 
    of the client and is checked to ensure it matches the
    IP address of the client sending it; however, an 
    unauthenticated, remote attacker can cause the cookie to
    be incorrectly parsed by adding a number of spaces to
    the IP address stored within the cookie, resulting in a
    bypass of the security mechanism. (CVE-2016-8022)

  - A security bypass vulnerability exists in the web
    interface due to improper handling of the nailsSessionId
    authentication cookie. An unauthenticated, remote
    attacker can exploit this, by brute-force guessing the
    server start authentication token within the cookie, to
    bypass authentication mechanisms. (CVE-2016-8023)

  - An HTTP response splitting vulnerability exists due to
    improper sanitization of carriage return and line feed
    (CRLF) character sequences passed to the 'info:0'
    parameter before being included in HTTP responses. An
    authenticated, remote attacker can exploit this to
    inject additional headers in responses and disclose
    sensitive information. (CVE-2016-8024)

  - A SQL injection (SQLi) vulnerability exists in the web
    interface due to improper sanitization of user-supplied
    input to the 'mon:0' parameter. An authenticated, remote
    attacker can exploit this to inject or manipulate SQL
    queries in the back-end database, resulting in the
    manipulation or disclosure of arbitrary data.
    (CVE-2016-8025)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10181");
  script_set_attribute(attribute:"see_also", value:"https://nation.state.actor/mcafee.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Endpoint Security for Linux (ENSL) version 10.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_dependencies("mcafee_vsel_detect.nbin");
  script_require_keys("installed_sw/McAfee VirusScan Enterprise for Linux");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "McAfee VirusScan Enterprise for Linux";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
vuln = FALSE;

# All VSEL <= 2.0.3 are vuln.
if (ver_compare(ver:version, fix:"2.0.3", strict:FALSE) <= 0) vuln = TRUE;

if (vuln)
{
  port = 0;
  report ='\nInstalled version : ' + version +
          '\nSolution          : Upgrade to McAfee Endpoint Security for Linux (ENSL) 10.2.0 or later.\n';
  security_report_v4(severity:SECURITY_HOLE, extra:report, port:port, xss:TRUE, sqli:TRUE, xsrf:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, version);
