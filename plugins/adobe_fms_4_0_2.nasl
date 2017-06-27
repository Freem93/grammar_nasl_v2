#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53895);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/09/28 23:36:00 $");

  script_cve_id("CVE-2010-3864", "CVE-2011-0612");
  script_bugtraq_id(44884, 47840);
  script_osvdb_id(69265, 72329);
  script_xref(name:"Secunia", value:"44589");

  script_name(english:"Adobe Flash Media Server < 3.5.6 / 4.0.2 Multiple Vulnerabilities (APSB11-11)");
  script_summary(english:"Checks version of Adobe Flash Media Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote media server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Media Server running on the remote host is
earlier than version 3.5.6 or 4.0.2.  Such versions are potentially
affected by the following vulnerabilities :

  - The server is affected by a memory corruption issue due 
    to a race condition in the TLS extension code provided
    by the bundled version of OpenSSL. A remote attacker 
    may be able to exploit this vulnerability to execute 
    arbitrary code on the server. (CVE-2010-3864)

  - The server is vulnerable to a denial of service attack
    due to an unspecified error related to processing 
    certain XML content. (CVE-2011-0612)");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-11.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Flash Media Server 3.5.6 / 4.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/13");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_media_server");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("adobe_fms_detect.nasl");
  script_require_ports("Services/rtmp");
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
  (ver[0] == 3 && ver[1] < 5) ||
  (ver[0] == 3 && ver[1] == 5 && ver[2] < 6) ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 2)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.5.6 / 4.0.2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The Adobe Flash Media Server version "+version+" on port "+port+" is not affected.");
