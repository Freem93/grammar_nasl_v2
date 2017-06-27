#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58595);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id("CVE-2011-1376", "CVE-2011-1377", "CVE-2011-4889");
  script_bugtraq_id(50310, 51420, 52723);
  script_osvdb_id(76563, 78332, 79711);

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 21 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote application server may be affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"IBM WebSphere Application Server 7.0 before Fix Pack 21 appears to be
running on the remote host.  As such, it is potentially affected by
the following vulnerabilities :

  - An unspecified cross-site scripting issue exists
    related to the 'Web 2.0 Messaging service'. (PM37840)

  - A security exposure when using WS-Security could result
    in a user gaining elevated privileges in applications
    using JAX-WS. (PM43585 / CVE-2011-1377)

  - Insecure file permissions are applied to the files in
    the '$WAS_HOME/systemapps/isclite.ear' and
    '$WAS_HOME/bin/client_ffdc' directories. These
    permissions can allow a local attacker to read or write
    files in those directories. Note this issue only affects
    the application on the IBM i operating system. (PM49712)

  - An error exists in the class
    'javax.naming.directory.AttributeInUseException' and can
    allow old passwords to still provide access. This error
    is triggered when passwords are updated by using IBM
    Tivoli Directory Server. (PM52049)"
  );
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  # PM43585
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21587536");
  # PM49712
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21569205");
  # 7.0.0.21 downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24031366");
  # ftp://public.dhe.ibm.com/software/websphere/appserv/support/fixes/PM53930/readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?609dea34");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27014463#70021");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 21 (7.0.0.21) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8880, embedded:0);


version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 21)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0.0.21' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
