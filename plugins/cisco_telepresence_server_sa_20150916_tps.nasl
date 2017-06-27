#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86123);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/17 04:41:38 $");

  script_cve_id("CVE-2015-6284");
  script_bugtraq_id(76758);
  script_osvdb_id(127643);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu28277");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150916-tps");

  script_name(english:"Cisco TelePresence Server Conference Control Protocol API URL Handling DoS (cisco-sa-20150916-tps)");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version, the Cisco TelePresence Server
running on the remote host is affected by a buffer overflow condition
in the Conference Control Protocol API due to improper validation of
user-supplied input. An unauthenticated, remote attacker can exploit
this, via a crafted URL, to cause a denial of service.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150916-tps
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?842f08b2");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuu28277");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuu28277.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_server_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_7010");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_mse_8710");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_on_multiparty_media_310");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_on_multiparty_media_320");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_on_virtual_machine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_server_detect.nasl");
  script_require_keys("Cisco/TelePresence_Server/Version", "Cisco/TelePresence_Server/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

model    = get_kb_item_or_exit("Cisco/TelePresence_Server/Model");
version  = get_kb_item_or_exit("Cisco/TelePresence_Server/Version");
fullname = "Cisco TelePresence " + model;

fix = '4.1(2.33)';

if (cisco_gen_ver_compare(a:version, b:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco TelePresence Server software", version);
