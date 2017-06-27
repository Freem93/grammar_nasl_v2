#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35659);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/04/16 22:15:22 $");

  script_cve_id("CVE-2009-0434");
  script_bugtraq_id(33700);
  script_osvdb_id(52595);

  script_name(english:"IBM WebSphere Application Server 6.1 < Fix Pack 21 Multiple Flaws");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute( attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"IBM WebSphere Application Server 6.1 before Fix Pack 21 appears to be
running on the remote host.  As such, it is reportedly affected by
multiple flaws :

  - Provided Performance Monitoring Infrastructure (PMI) is
    enabled, it may be possible for a local attacker to
    obtain sensitive information through 'Systemout.log' and
    'ffdc' files that are written by PerfServlet.

  - SSL Configuration settings attribute 'Security Level'
    does not correctly enforce the level of encryption used
    by the application server. (PK63182)");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?&uid=swg1PK63182");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007951#61021");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 21 (6.1.0.21) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880);


version = get_kb_item("www/WebSphere/"+port+"/version");
if (isnull(version)) exit(1, "Failed to extract the version from the IBM WebSphere Application Server instance listening on port " + port + ".");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 21)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.0.21' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
