#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59836);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_cve_id(
    "CVE-2012-0300",
    "CVE-2012-0301",
    "CVE-2012-0302",
    "CVE-2012-0303"
  );
  script_bugtraq_id(54133, 54134, 54135, 54136);
  script_osvdb_id(
    83261,
    83262,
    83263,
    83264
  );
  script_xref(name:"IAVB", value:"2012-B-0068");

  script_name(english:"Symantec Message Filter Multiple Vulnerabilities (SYM12-010)");
  script_summary(english:"Checks if about.jsp is accessible without authentication");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web management interface hosted on the remote web server has
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Brightmail Control Center (the web management interface
for Symantec Message Filter) hosted on the remote web server has the
following vulnerabilities :

  - Multiple information disclosure vulnerabilities.
    (CVE-2012-0300)

  - Session fixation. (CVE-2012-0301)

  - Unspecified cross-site scripting. (CVE-2012-0302)

  - Unspecified cross-site request forgery. (CVE-2012-0303)"
  );
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/bugtraq/2012/Jul/12");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120626_00
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?4345ed39");
  # http://www.symantec.com/business/support/index?page=content&id=TECH191487
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?df589738");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Symantec Message Filter 6.3 and apply patch smf_630_p231.

This patch is the last security update that will be provided for
Symantec Message Filter as the software is no longer supported. 
Consider migrating to a different product."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date",value:"2012/06/26");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/06/26");
  script_set_attribute(attribute:"plugin_publication_date",value:"2012/07/03");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:message_filter");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("symantec_message_filter_bcc_detect.nasl");
  script_require_keys("www/smf_bcc");
  script_require_ports("Services/www", 41080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:41080);
install = get_install_from_kb(appname:'smf_bcc', port:port, exit_on_fail:TRUE);

# TECH191487 says you can detect the presence of the patch by requesting
# about.jsp and try.do. requesting about.jsp checks if the info leak has been
# patched. requesting try.do checks if the XSS has been patched (i.e., a custom
# error page is being used). we can check for the presence of the patch in the
# latter by seeing if the default error page is being used
url = install['dir'] + '/about.jsp';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
match = eregmatch(string:res[2], pattern:"Version ([\d.]+)");
if (isnull(match))
  smf_ver = NULL;
else
  smf_ver = match[1];

url = install['dir'] + '/try.do';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
match = eregmatch(string:res[2], pattern:"Apache Tomcat/([\d.]+)");
if (isnull(match))
  tomcat_ver = NULL;
else
  tomcat_ver = match[1];

if (isnull(smf_ver) && isnull(tomcat_ver))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Message Filter', build_url(qs:install['dir'], port:port));

set_kb_item(name:'www/' + port + '/XSRF', value:TRUE);
set_kb_item(name:'www/' + port + '/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\nNessus determined the patch is missing per the instructions in' +
    '\nTECH191487.\n';

  if (!isnull(smf_ver))
  {
    report +=
      '\nThe following page does not redirect to the user logon page :\n\n' +
      build_url(qs:install['dir'] + '/about.jsp', port:port) + '\n';
  }
  if (!isnull(tomcat_ver))
  {
    report +=
      '\nThe following page does not display an error with the Symantec logo :\n\n' +
      build_url(qs:install['dir'] + '/try.do', port:port) + '\n';
  }

  security_warning(port:port, extra:report);
}
else security_warning(port);

