#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70118);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2013-3576");
  script_bugtraq_id(60471);
  script_osvdb_id(94191);
  script_xref(name:"CERT", value:"735364");
  script_xref(name:"EDB-ID", value:"26420");

  script_name(english:"HP System Management Homepage ginkgosnmp.inc Command Injection");
  script_summary(english:"Does a banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is affected by a command injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the web server's banner, the version of HP System
Management Homepage (SMH) hosted on the remote web server is earlier
than 7.2.2 and is, therefore, reportedly affected by a command
injection vulnerability.

An input validation error exists in the file 'ginkgosnmp.inc' related to
the last segment in a requested URL path.  This input is later used in
an 'exec' call and could allow an authenticated attacker to execute
arbitrary commands."
  );
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03895050-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee3d4911");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528713/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP System Management Homepage 7.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"HP System Management Homepage RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP System Management Homepage JustGetSNMPQueue Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/hp_smh");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


# Quickly check OS - only Linux
# and Windows are affected; ESX is not
if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  os = tolower(os);
  if (
    (
      "windows" >!< os &&
      "linux" >!< os
    )
    ||
    "esx" >< os
  )
    audit(AUDIT_OS_NOT, "Windows or Linux");
}

port = get_http_port(default:2381, embedded:TRUE);

install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
dir     = install['dir'];
version = install['ver'];
prod    = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");

if (version == UNKNOWN_VER) exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' is unknown.');

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt))
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' does not look valid ('+version+').');

fixed_version = '7.2.2.8';
if (ver_compare(ver:version_alt, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    source_line = get_kb_item("www/"+port+"/hp_smh/source");

    report = '\n  Product           : ' + prod;
    if (!isnull(source_line))
      report += '\n  Version source    : ' + source_line;
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
