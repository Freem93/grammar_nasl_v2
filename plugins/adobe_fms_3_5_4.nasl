#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48298);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2012/06/14 20:27:36 $");

  script_cve_id(
    "CVE-2010-2217", 
    "CVE-2010-2218", 
    "CVE-2010-2219", 
    "CVE-2010-2220"
  );
  script_bugtraq_id(42352, 42354, 42356, 42357);
  script_osvdb_id(67063, 67064, 67065, 67066);

  script_name(english:"Adobe Flash Media Server < 3.0.6 / 3.5.4 Multiple Vulnerabilities (APSB10-19)");
  script_summary(english:"Checks version of Adobe Flash Media Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote media server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote host is running Adobe Flash Media Server, an application
server for Flash-based applications. 

The version running on the remote host is earlier than version 3.0.6
or 3.5.4.  Such versions are potentially affected by the following
vulnerabilities :

  - An issue in a JS method could result in a denial of
    service condition. (CVE-2010-2218)

  - An issue in a JS method could allow arbitrary code 
    execution. (CVE-2010-2217)

  - A memory exhaustion issue could lead to a denial of
    service condition. (CVE-2010-2219)

  - A input validation issue could lead to a denial of
    service condition. (CVE-2010-2220)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-19.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Flash Media Server 3.0.6, 3.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_media_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("adobe_fms_detect.nasl");
  script_require_ports("Services/rtmp", 1111, 1935, 19350);
  script_require_keys("rtmp/adobe_fms");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item_or_exit("Services/rtmp");
version = get_kb_item_or_exit("rtmp/" + port + "/adobe_fms/version");
source = get_kb_item_or_exit("rtmp/" + port + "/adobe_fms/version_source");

ver = split(version, sep:'.', keep:FALSE);
for (i=0;i<max_index(ver); i++)
  ver[i] = int(ver[i]);
  
if (
  ver[0] < 3 ||
  (
    ver[0] == 3 &&
    (
      (ver[1] == 0 && ver[2] < 6) ||
      (ver[1] == 5 && ver[2] < 4)
    )
  )
)
{
  if (report_verbosity)
  {
    report = 
      '\n' +
      'Version source : ' + source +
      '\n' +
      'Installed version : ' + version +
      '\n' +
      'Fixed version : 3.0.6 / 3.5.4\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The Adobe Flash Media Server version "+version+" on port "+port+" is not affected.");
