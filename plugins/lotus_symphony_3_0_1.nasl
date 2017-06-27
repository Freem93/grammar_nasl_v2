#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59109);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/05/17 14:52:35 $");

  script_cve_id("CVE-2012-0192");
  script_bugtraq_id(51591);
  script_osvdb_id(78345);

  script_name(english:"IBM Lotus Symphony < 3.0.1 Embedded Image File Handling Remote Overflows");
  script_summary(english:"Checks version of IBM Lotus Symphony");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application that is affected by multiple
integer overflows."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of IBM Lotus Symphony on the remote host was found to be
earlier than 3.0.1.  As such, it is reportedly affected by multiple
integer overflows in vlcmi.dll.  These vulnerabilities can be
triggered by a malicious JPEG or PNG image object embedded in a .DOC
file, resulting in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21578684");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to IBM Lotus Symphony 3.0.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_symphony");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("lotus_symphony_installed.nasl");
  script_require_keys("SMB/Lotus_Symphony/Installed");
  
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

appname = "Lotus Symphony";

kb_base = "SMB/Lotus_Symphony/";
port = get_kb_item("SMB/transport");

get_kb_item_or_exit(kb_base + "Installed");
version = get_kb_item_or_exit(kb_base + "Version");

# extract build timestamp
item = eregmatch(pattern:"([0-9]+)-([0-9]+)$", string:version);
if (isnull(item)) exit(1, "Error parsing the version string ("+version+").");

# date/time
dt = int(item[1]);
tm = int(item[2]);

if (
  dt < 20120110 ||
  (dt == 20120110 && tm < 2000)
)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item(kb_base + "Path");
    ver_ui = get_kb_item(kb_base + "Version_UI");
    report = '\n  Path              : ' + path + 
             '\n  Installed version : ' + ver_ui +
             '\n  Fixed version     : 3.0.1 (3.0.1.20120110-2000)\n';
    security_hole(port:port,extra:report);
  }
  else security_hole(port);
  exit(0);
} 
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
