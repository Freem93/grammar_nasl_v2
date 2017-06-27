#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38832);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_cve_id("CVE-2008-5077", "CVE-2008-5814", "CVE-2009-1418");
  script_bugtraq_id(35031);
  script_osvdb_id(51164, 53532, 54608);
  script_xref(name:"Secunia", value:"35108");

  script_name(english:"HP System Management Homepage < 3.0.1.73 Multiple Flaws");
  script_summary(english:"Checks version of HP SMH");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");

  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the HP System
Management Homepage install on the remote host is earlier than
3.0.1.73.  Such versions are reportedly affected by multiple flaws :

  - A weakness in PHP could be exploited to perform cross-
    site scripting attacks, provided PHP directive 'display
    errors' is enabled. (CVE-2008-5814)

  - A vulnerability in OpenSSL versions prior to 0.9.8i
    could be exploited to bypass the validation of the
    certificate chain. (CVE-2008-5077)

  - Windows and Linux versions of SMH are affected by a
    cross-site scripting vulnerability. (CVE-2009-1418)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01743291
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5252a6f9");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01745065
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e2a507a8"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to HP System Management Homepage 3.0.1.73 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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


port = get_http_port(default:2381, embedded:TRUE);


install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
prod = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");


# nb: HP only says Linux and Windows are affected
if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Windows" >!< os && "Linux" >!< os) exit(0, "The remote host appears to be running "+os+", and only Windows and Linux installs are affected.");
}


dir = install['dir'];
version = install['ver'];
if (version == UNKNOWN_VER)
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' is unknown.');

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt))
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' does not look valid ('+version+').');

fixed_version = '3.0.1.73';
if (ver_compare(ver:version_alt, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source_line = get_kb_item("www/"+port+"/hp_smh/source");

    report = '\n  Product           : ' + prod;
    if (!isnull(source_line))
      report += '\n  Version source    : ' + source_line;
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else exit(0, prod+" "+version+" is listening on port "+port+" and is not affected.");
