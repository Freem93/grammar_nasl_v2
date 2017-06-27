#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69449);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id(
    "CVE-2012-2098",
    "CVE-2013-0169",
    "CVE-2013-0597",
    "CVE-2013-1768",
    "CVE-2013-1862",
    "CVE-2013-1896",
    "CVE-2013-2967",
    "CVE-2013-2976",
    "CVE-2013-3029",
    "CVE-2013-4004",
    "CVE-2013-4005"
  );
  script_bugtraq_id(
    53676,
    57778,
    59826,
    60534,
    60724,
    61129,
    61901,
    61935,
    61937,
    61940,
    61941
  );
  script_osvdb_id(
    82161,
    89802,
    89804,
    89848,
    89865,
    93366,
    94233,
    94743,
    94744,
    94747,
    94748,
    95498,
    96507,
    96508
  );

  script_name(english:"IBM WebSphere Application Server 8.0 < Fix Pack 7 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote application server may be affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"IBM WebSphere Application Server 8.0 before Fix Pack 7 appears to be
running on the remote host.  It is, therefore, potentially affected by
the following vulnerabilities :

  - A flaw exists related to Apache Ant and file
    compression that could lead to denial of service
    conditions. (CVE-2012-2098 / PM90088)

  - The TLS protocol in the GSKIT component is vulnerable
    to a plaintext recovery attack.
    (CVE-2013-0169 / PM85211)

  - A flaw exists relating to OAuth that could allow a
    remote attacker to obtain someone else's credentials.
    (CVE-2013-0597 / PM85834 / PM87131)

  - A flaw exists relating to OpenJPA that is triggered
    during deserialization, which could allow a remote
    attacker to write to the file system and potentially
    execute arbitrary code. Note the vendor states this
    application is not directly affected by this flaw;
    however, this application does include the affected
    version of OpenJPA. (CVE-2013-1768 / PM86780)

  - An input validation flaw exists in the optional
    'mod_rewrite' module in the included IBM HTTP Server
    that could allow arbitrary command execution via
    HTTP requests containing certain escape sequences.
    (CVE-2013-1862 / PM87808)

  - A flaw exists related to the optional 'mod_dav'
    module in the included IBM HTTP Server that could
    allow denial of service conditions.
    (CVE-2013-1896 / PM89996)

  - User-supplied input validation errors exist related to
    the administrative console that could allow cross-site
    scripting attacks.
    (CVE-2013-2967 / PM78614, CVE-2013-4004 / PM81571,
    CVE-2013-4005 / PM88208)

  - An information disclosure vulnerability exists related
    to incorrect caching by the administrative console.
    (CVE-2013-2976 / PM79992)

  - A user-supplied input validation error exists that could
    allow cross-site request forgery (CSRF) attacks to be
    carried out. (CVE-2013-3029 / PM88746)"
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_potential_security_exposure_in_ibm_http_server_cve_2013_1862_pm87808?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?187690fd");
  # Fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21644047");
  # Downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24035457");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_potential_security_vulnerabilities_fixed_in_ibm_websphere_application_server_8_0_0_7?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1c66192");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 7 for version 8.0 (8.0.0.7) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8880, embedded:0);


version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server " + version + " instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8 && ver[1] == 0 && ver[2] == 0 && ver[3] < 7)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.0.7' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "WebSphere", port, version);
