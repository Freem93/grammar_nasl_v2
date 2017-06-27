#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86544);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/21 15:06:14 $");

  script_cve_id("CVE-2015-6318");
  script_bugtraq_id(77056);
  script_osvdb_id(128676);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv11969");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20141007-vcs");

  script_name(english:"Cisco TelePresence VCS Expressway 8.5.1 / 8.5.2 request-xconfdump Symbolic Link Local File Manipulation (cisco-sa-20141007-vcs)");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a file manipulation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Cisco
TelePresence Video Communication Server (VCS) Expressway running on
the remote host is affected by a file manipulation vulnerability in
request-xconfdump due to insufficient protection of files. An
authenticated, local attacker can exploit this, via a malicious
symbolic link to an unauthorized location, to insert arbitrary content
into arbitrary linked files.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151007-vcs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9fb6016");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv11969");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco TelePresence VCS Expressway 8.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version  = get_kb_item_or_exit("Cisco/TelePresence_VCS/Version");
fullname = "Cisco TelePresence Device";

if (version =~ "^8\.5\.[12]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 8.6' +
             '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_DEVICE_NOT_VULN, fullname, version);
