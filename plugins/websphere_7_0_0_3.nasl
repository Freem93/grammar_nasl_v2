#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36133);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2009-0508",
    "CVE-2009-0892",
    "CVE-2009-0903",
    "CVE-2009-1172",
    "CVE-2009-1173",
    "CVE-2009-1174"
  );
  script_bugtraq_id(34104, 34330, 34358, 34506, 35594, 35610);
  script_osvdb_id(52620, 53251, 53252, 53253, 53268, 56161);
  script_xref(name:"Secunia", value:"34131");
  script_xref(name:"Secunia", value:"34461");

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 3");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 7.0 before Fix Pack 3 appears to be
running on the remote host.  As such, it is reportedly affected by
multiple vulnerabilities :

  - Under certain conditions it may be possible to access
    administrative console user sessions. (PK74966)

  - The administrative console is affected by a cross-site
    scripting vulnerability. (PK77505)

  - If APAR PK41002 has been applied, a vulnerability in the
    JAX-RPC WS-Security component could incorrectly
    validate 'UsernameToken'. (PK75992)

  - Sample applications shipped with IBM WebSphere
    Application Server are affected by cross-site scripting
    vulnerabilities. (PK76720)

  - Certain files associated with interim fixes for Unix-
    based versions of IBM WebSphere Application Server are
    built with insecure file permissions. (PK77590)

  - The Web Services Security component is affected by an
    unspecified security issue in digital-signature
    specification. (PK80596)

  - It may be possible for an attacker to read arbitrary
    application-specific war files. (PK81387)

  - A security bypass caused by inbound requests that lack
    a SOAPAction or WS-Addressing Action. (PK72138)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24022693");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24022456");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21367223");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27014463#7003");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 3 (7.0.0.3) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 200, 264, 287, 310);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/27");

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

port = get_http_port(default:8880, embedded: 0);


version = get_kb_item("www/WebSphere/"+port+"/version");
if (isnull(version)) exit(1, "Failed to extract the version from the IBM WebSphere Application Server instance listening on port " + port + ".");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 3)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report = 
      '\n  Source            : ' + source + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0.0.3' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
