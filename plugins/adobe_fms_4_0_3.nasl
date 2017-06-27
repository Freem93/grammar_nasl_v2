#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55811);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/09/26 16:33:57 $");

  script_cve_id("CVE-2011-2132");
  script_bugtraq_id(49103);
  script_osvdb_id(74431);
  script_xref(name:"Secunia", value:"45585");

  script_name(english:"Adobe Flash Media Server < 3.5.7 / 4.0.3 Denial of Service (APSB11-20)");
  script_summary(english:"Checks version of Adobe Flash Media Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote media server is affected by a denial of service
vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Media Server running on the remote host is
earlier than versions 3.5.7 / 4.0.3.  As such, it is potentially
affected by a memory corruption issue that could lead to a denial of
service.");

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Oct/531");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-20.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Flash Media Server 3.5.7 / 4.0.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/10");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_media_server");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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
  (ver[0] == 3 && ver[1] == 5 && ver[2] < 7) ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 3)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.5.7 / 4.0.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The Adobe Flash Media Server version "+version+" on port "+port+" is not affected.");
