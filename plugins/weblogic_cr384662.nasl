#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17743);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2008-5461");
  script_bugtraq_id(33177);
  script_osvdb_id(51314);

  script_name(english:"Oracle WebLogic WLS Unspecified Vulnerability (CVE-2008-5461)");
  script_summary(english:"Checks the version of Oracle WebLogic");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Oracle WebLogic Server has an unspecified vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported banner, the version of Oracle WebLogic
Server running on the remote host has an unspecified vulnerability in
WebLogic Console that can be exploited remotely and may allow
information disclosure and elevation of privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.oracle.com/technetwork/topics/security/2811-100497.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade and/or apply the appropriate patch as described in Oracle's
advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Oracle Secure Backup 10.2.0.2 RCE (Windows)");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bea:weblogic_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
 
  script_dependencies("weblogic_detect.nasl");
  script_require_keys("www/weblogic");
  script_require_ports("Services/www", 80, 7001);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:7001);

get_kb_item_or_exit("www/weblogic/" + port + "/installed");

version = get_kb_item_or_exit("www/weblogic/" + port + "/version", exit_code:1);
service_pack = get_kb_item("www/weblogic/" + port + "/service_pack");

if (isnull(service_pack)) version_ui = version;
else version_ui = version + ' ' + service_pack;

fix = '';
if (version == "7.0" && (isnull(service_pack) || service_pack =~ "^SP[1-7]$"))
{
  fix = '7.0 SP7 with #7824512';
}
else if (version == "8.1" && (isnull(service_pack) || service_pack =~ "^SP[1-6]$"))
{
  fix = '8.1 SP6 with #7824519';
}
else if (version == "9.0" && isnull(service_pack))
{
  fix = '9.0 with #7824963 and #7824525';
}
else if (version == "9.1" && isnull(service_pack))
{
  fix = '9.1 with CR384662';
}
else if (version == "9.2" && (isnull(service_pack) || service_pack =~ "^MP[1-3]$"))
{
  fix = '9.2 MP3 with CR384662';
}
else if (version == "10.0" && (isnull(service_pack) || service_pack == "MP1"))
{
  fix = '10.0 MP1 with CR384662';
}
else if (version == "10.3" && isnull(service_pack))
{
  fix = '10.3 with CR384662';
}
else exit(0, "The Oracle WebLogic "+version_ui+" install listening on port "+port+" is not affected.");


cr_patch = "CR384662";
if (get_kb_item("www/weblogic/" + port + "/cr_patches/" + cr_patch))
  exit(0, "The Oracle WebLogic "+version_ui+" install listening on port "+port+" is not affected since it has the patch for "+cr_patch+".");

if (report_verbosity > 0) 
{
  source = get_kb_item_or_exit("www/weblogic/" + port + "/source", exit_code:1);
  report = 
    '\n  Source            : ' + source +
    '\n  Installed version : ' + version_ui +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
