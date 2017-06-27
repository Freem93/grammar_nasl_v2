#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36161);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2008-4284",
    "CVE-2009-0508",
    "CVE-2009-0855",
    "CVE-2009-0856",
    "CVE-2009-0891",
    "CVE-2009-0892",
    "CVE-2009-1172"
  );
  script_bugtraq_id(34330, 34501, 34502, 35610);
  script_osvdb_id(
    52402,
    52596,
    52620,
    52829,
    53251,
    53268,
    53990,
    56151,
    56152,
    56153,
    56154,
    56155,
    56156,
    56157,
    56158,
    56159
  );
  script_xref(name:"Secunia", value:"33729");
  script_xref(name:"Secunia", value:"34131");
  script_xref(name:"Secunia", value:"34283");

  script_name(english:"IBM WebSphere Application Server < 6.1.0.23 Multiple Flaws");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.1 before Fix Pack 23 appears to
be installed on the remote host.  Such versions are reportedly affected
by multiple vulnerabilities :

  - Provided an attacker has valid credentials, it may be
    possible to hijack an authenticated session. (PK66676)

  - It may be possible for a remote attacker to redirect
    users to arbitrary sites using ibm_security_logout
    servlet. (PK71126)

  - Under certain conditions it may be possible to access
    administrative console user sessions. (PK74966)

  - If APAR PK41002 has been applied, a vulnerability in
    the JAX-RPC WS-Security component could incorrectly
    validate 'UsernameToken'. (PK75992)

  - Sample applications shipped with IBM WebSphere
    Application Server are affected by cross-site scripting
    vulnerabilities. (PK76720)

  - The administrative console is affected by a cross-site
    scripting vulnerability. (PK77505)

  - It may be possible for an attacker to read arbitrary
    application-specific war files. (PK81387)");

  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21367223");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27007951#61023");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 23 (6.1.0.23) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 59, 79, 200, 287);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 23)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.0.23' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
