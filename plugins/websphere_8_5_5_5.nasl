#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83290);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/03/07 16:58:29 $");

  script_cve_id(
    "CVE-2015-0174",
    "CVE-2015-0175",
    "CVE-2015-1882",
    "CVE-2015-1920"
  );
  script_bugtraq_id(
    74215,
    74222,
    74223,
    74439
  );
  script_osvdb_id(
    119702,
    119703,
    119705,
    121577
  );

  script_name(english:"IBM WebSphere Application Server Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is
version 6.1.0.47 / 7.0.0.37 / 8.0.0.10 / 8.5.5.5 or prior. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    SNMP component due to improper handling of configuration
    data. An authenticated, remote attacker can exploit this
    disclose sensitive information. (CVE-2015-0174)

  - An unspecified flaw exists in the liberty profile due to
    improper handling of authData elements. An
    authenticated, remote attacker can exploit this to gain
    elevated privileges. (CVE-2015-0175)

  - An unspecified flaw exists in the liberty profile that
    is triggered when the run-as user for EJB is not honored
    under multi-threaded race conditions. An authenticated,
    remote attacker can exploit this to gain elevated
    privileges. (CVE-2015-1882)

  - A flaw exists that allows a remote attacker to execute
    arbitrary code by connecting to a management port using
    a specific sequence of instructions. (CVE-2015-1920)");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21883573");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21697368");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg24039898");
  script_set_attribute(attribute:"solution", value:
"Apply Interim Fix PI38302.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8880, embedded:0);

version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

app_name = "IBM WebSphere Application Server";

if (version =~ "^[0-9]+(\.[0-9]+)?$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

if (version =~ "^8\.5\.5\.")
{
  cutoff = '8.5.5.5';
  minimum = '8.5.5.0';
}
else if (version =~ "^8\.5\.0\.")
{
  cutoff = '8.5.0.2';
  minimum = '8.5.0.0';
}
else if (version =~ "^8\.0\.")
{
  cutoff = '8.0.0.10';
  minimum = '8.0.0.3';
}
else if (version =~ "^7\.0\.")
{
  cutoff = '7.0.0.37';
  minimum = '7.0.0.21';
}
else if (version =~ "^6\.1\.")
{
  cutoff = '6.1.0.47';
  minimum = '6.1.0.47';
}
else cutoff = NULL;

if (!isnull(cutoff) && ver_compare(ver:version, fix:cutoff, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Minimum fix pack  : ' + minimum +
      '\n  Interim fix       : PI38302' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
