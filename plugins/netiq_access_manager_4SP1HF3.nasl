#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81405);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/19 15:50:07 $");

  script_cve_id("CVE-2014-5214","CVE-2014-5215","CVE-2014-5216","CVE-2014-5217");
  script_osvdb_id(
    116056,
    116057,
    116058,
    116059,
    116061,
    116062,
    116063,
    116064
  );
  script_bugtraq_id(71745,71754,71755,71826);

  script_name(english:"NetIQ Access Manager 4.0 < 4.0 SP1 Hotfix 3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of NetIQ Access Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of NetIQ Access Manager 4.0
without service pack 1 hotfix 3. It is, therefore, affected by the
following vulnerabilities :

  - An XML Entity Injection (XXE) flaw exists in the 'query'
    parameter of the webacc servlet that can allow an
    authenticated user to view the contents of any file on
    the system that the user running the web application has
    access to, including the '/etc/password' file.
    (CVE-2014-5214)

  - An authenticated user, via the 'debug.jsp' and
    'dev_services.jsp' pages, can gain access to the
    following protected system properties :
      - com.volera.vcdn.monitor.password
      - com.volera.vcdn.alert.password
      - com.volera.vcdn.sync.password
      - com.volera.vcdn.scheduler.password
      - com.volera.vcdn.publisher.password
      - com.volera.vcdn.application.sc.scheduler.password
      - com.volera.vcdn.health.password
    (CVE-2014-5215)

  - Multiple reflected cross-site scripting (XSS) flaws
    exist in the parameters on various pages.
    (CVE-2014-5216)

  - A cross-site request forgery (XSRF) vulnerability exists
    in the webacc servlet that allows an attacker, using a
    specially crafted request, to change the administrative
    password of the Administration Console. However, an
    administrator must be tricked into executing the request
    within the context of an authenticated session.
    (CVE-2014-5217)");

  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/support/kb/doc.php?id=7015993");
  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/support/kb/doc.php?id=7015994");
  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/support/kb/doc.php?id=7015995");
  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/support/kb/doc.php?id=7015996");
  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/support/kb/doc.php?id=7015997");
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20141218-2_Novell_NetIQ_Access_Manager_Multiple_Vulnerabilities_v10.tx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad1a1c9a");

  script_set_attribute(attribute:"solution", value:"Upgrade to Access Manager 4.0 Service Pack 1 and apply Hotfix 3");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netiq:access_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("netiq_access_manager_detect.nbin","netiq_access_manager_installed.nbin");
  script_require_keys("installed_sw/NetIQ Access Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http_func.inc");

appname  = "NetIQ Access Manager";
installs = get_combined_installs(app_name:appname,exit_if_not_found:TRUE);
installs = installs[1];

version = FALSE;
hotfix  = FALSE;
port    = FALSE;
path    = FALSE;
# We will either see an install from the WebUI
# or from the local detect or both.  So at most
# installs is a list of 2 things, it is not
# possible to have more than one version installed
# at a time
foreach install (installs)
{
  iver  = install['version'];
  ihfx  = install['hotfix' ];
  iport = install['port'   ];

  if(!version || (iver != version && iver != UNKNOWN_VER))
    version = iver;
  if(!hotfix  || (ihfx != hotfix  && ihfx != UNKNOWN_VER))
    hotfix  = ihfx;
  if(!path)
    path = install["path"];
  # We always prefer the remote detects port/path
  if(!isnull(iport))
  {
    port = iport;
    path = install["path"];
  }
}
inthf = 0;
if(hotfix != "None" && hotfix != UNKNOWN_VER)
  inthf = int(hotfix);

if(version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER,appname);

# Got a port so we can show URL instead of FS Path
if(port) path = build_url(port:port,qs:path);
else     port = 0;

# hotfix == UNKNOWN_VER : couldn't determine hotfix
# hotfix == "None"      : determined hotfix, but there isn't one
# hotfix == some number : determined hotfix
if(version == "4.0.1" && hotfix == UNKNOWN_VER && report_paranoia <= 1)
  exit(1,"Hotfix level unknown, this plugin will only run if 'Report paranoia' is set to 'Paranoid'");

# Report versions of vars
rversion = version;
if(inthf != 0)
  rversion += " HF"+hotfix;

rport = port;
if(port == 0)
{
  rport = get_kb_item('SMB/transport');
  if(isnull(rport)) rport = 445;
}

if ( version == "4.0.0" || (version == "4.0.1" && inthf < 3) )
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/XSRF', value: TRUE);
  if (report_verbosity > 0)
  {
    if(port != 0)
      report = '\n  URL               : ' + path;
    else
      report = '\n  Path              : ' + path;
    report  += '\n  Installed version : ' + rversion +
               '\n  Fixed version     : 4.0.1 HF3\n';
    security_warning(port:rport, extra:report);
  }
  else security_warning(rport);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN,appname,rversion);
