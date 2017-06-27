#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46203);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2010-1316");
  script_bugtraq_id(39638);
  script_xref(name:"OSVDB", value:"63744");
  script_xref(name:"Secunia", value:"39270");

  script_name(english:"Tembria Server Monitor < 5.6.1 Denial of Service");
  script_summary(english:"Checks version of Tembria Server Monitor");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a server-monitoring application that is
affected by a remote buffer overflow vulnerability.");

  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Tembria Server Monitor 
earlier than 5.6.1.  Such versions are reportedly affected by a
buffer overflow vulnerability when handling specially crafted HTTP
requests.  An attacker, exploiting this flaw, could crash the affected
service.");

  script_set_attribute(attribute:"see_also", value:"http://www.corelan.be:8800/advisories.php?id=CORELAN-10-022");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Apr/133");
  script_set_attribute(attribute:"see_also", value:"http://www.tembria.com/products/servermonitor/versionhistory.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Tembria Server Monitor 5.6.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");
  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("tembria_server_monitor_detect.nasl");
  script_require_keys("www/tembria_monitor");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, asp:TRUE, embedded:TRUE);

version = get_kb_item("www/tembria_monitor/"+port+"/version");
if (isnull(version)) exit(0, "The web server on port "+port+" doesn't appear to be Tembria Server Monitor.");
if (int(version) == 0) exit(1, "The web server on port "+port+" has an unknown version of Tembria Server Monitor.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
{
  ver[i] = int(ver[i]);
}

if (
  ver[0] < 5 ||
  (
    ver[0] == 5 &&
    (
      ver[1] < 6 || 
      (ver[1] == 6 && ver[2] < 1)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 5.6.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port, extra:report);
}
else exit(0, "The remote host is not affected because Tembria Server Monitor version "+version+" is installed.");
