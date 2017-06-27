#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50023);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2011/10/24 19:37:28 $");

  script_bugtraq_id(43242);
  script_osvdb_id(68136);
  script_xref(name:"Secunia", value:"27994");

  script_name(english:"Novell PlateSpin Orchestrate Remote Code Execution");
  script_summary(english:"Checks version of Novell PlateSpin Orchestrate"); 
 
  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host.");
  script_set_attribute(attribute:"description", value:
"Novell PlateSpin Orchestrate is installed on the remote host. 

According to its version, this software does not properly sanitize
user data before calling a graph rendering module which reportedly can
be abused by an unauthenticated, remote attacker to run arbitrary code
and gain complete control of the affected system.

Note that Nessus only checked the version of the installed software.");
  script_set_attribute(attribute:"see_also", value: "http://www.zerodayinitiative.com/advisories/ZDI-10-178/");
  script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=BkIPy5JtULM~");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Novell PlateSpin Orchestrate 2.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "ssh_get_info.nasl");
  script_require_ports("Services/www", 8001);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ver = make_array();

# Try local test first
rpm = get_kb_item("Host/SuSE/rpm-list");
if ("novell-zenworks-zos-server-" >< rpm)
{
  foreach line (split(egrep(string: rpm, pattern: "^novell-zenworks-zos-"), keep: 0))
  {
    v = eregmatch(string: chomp(line), pattern: "^novell-zenworks-zos-[a-z-]+-([0-9.]+)-[0-9]+");
    if (! isnull(v)) ver[v[1]] ++;
  }
  l = keys(ver);
  if (isnull(l))
    exit(1, "No version number was obtained from the list of RPMs on the remote host.");
  l = make_list(l); 
  if (max_index(l) > 1)
    exit(1, max_index(l) + " versions were collected from the list of RPMs on the remote host.");
  port = 0;
}
else
{
  # Remote version check
  port = get_http_port(default: 8001, embedded: 1);

  b = get_http_banner(port: port, exit_on_fail: 1);
  if (! egrep(string: b, pattern: "^Server: *PlateSpin Orchestrate/2"))
    exit(0, "The web server on port "+port+" is not PlateSpin Orchestrate.");

  b = http_get_cache(port: port, item: "/", exit_on_fail: 1);
  b = egrep(string:b, pattern: "(zosagent|zosclients).*\.(exe|sh|gmg|tar\.gz|rpm)");

  foreach l (split(b))
  {
    v = eregmatch(string: l, pattern: "(zosagent|zosclients).*[^0-9]_([0-9]+[_0-9]+)(_[a-z_]+)?\.(exe|sh|gmg|tar\.gz|rpm)[^a-z]");
    if (! isnull(v))
    {
      ver[v[2]] ++;
    }
  }
  l = keys(ver);
  if (isnull(l))
    exit(1, "No version number was grabbed on "+build_url(port:port, qs:"/")+".");
  l = make_list(l); 
  if (max_index(l) > 1)
    exit(1, max_index(l) + " versions were collected on "+build_url(port:port, qs:"/")+".");
}

ver = str_replace(string: l[0], find: "_", replace: ".");

set_kb_item(name: "PlateSpinOrchestrate/Version", value: ver);

if (ver_compare(ver: ver, fix: "2.5.0", strict: 0) < 0)
{
  if (report_verbosity > 0)
  {
    info = '\n  Installed version : ' + ver + 
           '\n  Fixed version     : 2.5.0\n';
    security_hole(port:port, extra:info);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'Novell PlateSpin Orchestrate version '+ver+' is installed and not affected.');
