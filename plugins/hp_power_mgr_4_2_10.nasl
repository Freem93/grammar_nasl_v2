#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44109);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_cve_id("CVE-2009-2685", "CVE-2009-3999", "CVE-2009-4000");
  script_bugtraq_id(36933, 37866, 37867, 37873);
  script_osvdb_id(59684, 61848, 61849);
  script_xref(name:"EDB-ID", value:"18015");
  script_xref(name:"Secunia", value:"37276");
  script_xref(name:"Secunia", value:"37280");

  script_name(english:"HP Power Manager < 4.2.10");
  script_summary(english:"Checks the version of HPPM");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The power management application installed on the remote host has
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of HP Power Manager is less than 4.2.10, and as
such has the following vulnerabilities :

  - Adequate bounds checking is not performed on the
    'Login' parameter of the login page, which could lead to
    a buffer overflow.  A remote, unauthenticated attacker
    could exploit this to execute arbitrary code as SYSTEM.
    (CVE-2009-2685)

  - Adequate bounds checking is not performed on the 'fileName'
    or 'LogType' parameters of 'formExportDataLogs', which
    could lead to a buffer overflow.  A remote, authenticated
    attacker could exploit this to execute arbitrary code as
    SYSTEM. (CVE-2009-3999)

  - The 'fileName' parameter of 'formExportDataLogs' has a
    directory traversal vulnerability.  A remote, authenticated
    attacker could exploit this to overwrite arbitrary files with
    almost arbitrary data.  This could result in a denial of
    service or arbitrary code execution as SYSTEM.
    (CVE-2009-4000)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-081/");
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/secunia_research/2009-47/"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01905743
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6a0c43e"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01971741
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09f023c2"
  );
  # http://h18004.www1.hp.com/products/servers/proliantstorage/power-protection/software/power-manager/pm3-dl.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d601101"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to HP Power Manager 4.2.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Power Manager \'formExportDataLogs\' Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(22, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:power_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_power_mgr_web_detect.nasl");
  script_require_keys("www/hp_power_mgr");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, embedded:TRUE);

install = get_install_from_kb(appname:'hp_power_mgr', port:port);
if (isnull(install))
  exit(1, "No HP Power Manager installs on port "+port+" were found in the KB.");

version = install['ver'];
if (version == UNKNOWN_VER)
  exit(1, 'The version of HP Power Manager on port '+port+' is unknown.');

ver = split(version, sep:'.', keep:FALSE);
fix = split('4.2.10', sep:'.', keep:FALSE);
vuln = FALSE;

for (i = 0; i < max_index(ver) && !vuln; i++)
{
  if (int(ver[i]) < int(fix[i])) vuln = TRUE;
  else if (int(ver[i]) > int(fix[i])) break;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\n  URL               : '+build_url(port:port, qs:install['dir']+"/index.asp")+
             '\n  Installed Version : '+version+
             '\n  Fixed Version     : 4.2.10\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'HP Power Manager version '+version+' is listening on port "+port+" and thus not affected.');

