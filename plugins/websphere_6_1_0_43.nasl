#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58594);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id(
    "CVE-2011-1376",
    "CVE-2011-1377",
    "CVE-2011-4889",
    "CVE-2012-0193",
    "CVE-2012-0716",
    "CVE-2012-0717",
    "CVE-2012-0720"
  );
  script_bugtraq_id(
    50310,
    51420,
    51441,
    52250,
    52721,
    52722,
    52723,
    52724
  );
  script_osvdb_id(76563, 78321, 78332, 79711, 83123, 83155, 83156);

  script_name(english:"IBM WebSphere Application Server 6.1 < 6.1.0.43 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote application server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"IBM WebSphere Application Server 6.1 before Fix Pack 43 appears to be
running on the remote host.  As such, it is potentially affected by
the following vulnerabilities :

  - An unspecified error exists related to WS-Security
    enabled JAX-RPC applications. (PM45181)

  - Insecure file permissions are applied to the files in
    the '$WAS_HOME/systemapps/isclite.ear' and
    '$WAS_HOME/bin/client_ffdc' directories. These
    permissions can allow a local attacker read or write
    files in those directories. Note this issue only
    affects the application on the IBM i operating system.
    (PM49712)

  - An error exists in the class
    'javax.naming.directory.AttributeInUseException' and can
    allow old passwords to still provide access. This error
    is triggered when passwords are updated by using IBM
    Tivoli Directory Server. (PM52049)

  - Unspecified cross-site scripting issues exist related to
    the administrative console. (PM52274, PM53132)

  - SSL client certificate authentication can be bypassed
    when all of the following are true (PM52351) :

      - SSL is enabled with 'SSLEnable'
      - SSL client authentication is enabled with
        'SSLClientAuth required_reset'. This is not enabled
        by default. Also note, 'SSLClientAuth required' is
        not affected
      - SSLv2 has not been disabled with
        'SSLProtocolDisable SSLv2'
      - 'SSLClientAuthRequire' is not enabled

  - An issue related to the weak randomization of Java hash
    data structures can allow a remote attacker to cause a
    denial of service with maliciously crafted POST requests.
    (PM53930)"
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/potential_security_vulnerability_when_using_web_based_applications_on_ibm_websphere_application_server_due_to_java_hashtable_implementation_vulnerability_cve_2012_0193?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca3789f7");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21587015");
  # PM53930 Alert
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21577532");
  # ftp://public.dhe.ibm.com/software/websphere/appserv/support/fixes/PM53930/readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?609dea34");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007951#61043");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 43 (6.1.0.43) or
later.

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880, embedded:FALSE);


version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 43)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.0.43' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
