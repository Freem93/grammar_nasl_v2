#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59195);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_cve_id("CVE-2012-2369");
  script_bugtraq_id(53557);
  script_osvdb_id(82124);

  script_name(english:"Pidgin OTR < 3.2.1 Format String");
  script_summary(english:"Checks version of Pidgin OTR");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by a
remote format string vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Pidgin OTR (Off-the-Record) installed on the remote
Windows host is prior to 3.2.1 and is, therefore, affected by a format
string vulnerability that could allow a remote attacker to execute
arbitrary code on the affected host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cypherpunks.ca/otr/index.php#news");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2012/q2/335");
  script_set_attribute(attribute:"solution", value:"Upgrade to Pidgin OTR 3.2.1 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:otr:pidgin-otr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("pidgin_otr_installed.nasl");
  script_require_keys("SMB/Pidgin_OTR/Installed");
  
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

appname = "Pidgin OTR";
kb_base = "SMB/Pidgin_OTR/";

get_kb_item_or_exit(kb_base + "Installed");
ver_str = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

# 3.2.1-1 -> 3.2.1, drop revision information if present
# we don't need it for check
item = eregmatch(pattern:"([0-9\.]+)", string:ver_str);
version = item[1];

fix = "3.2.1";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{  
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path + 
             '\n  Installed version : ' + ver_str +
             '\n  Fixed version     : 3.2.1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
} 
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_str, path);
