#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93108);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/27 16:08:35 $");

  script_cve_id("CVE-2016-1352");
  script_bugtraq_id(86029);
  script_osvdb_id(137039);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160413-ucs");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv33856");

  script_name(english:"Cisco UCS Central Software < 1.3(1c) HTTP Request Handling RCE");
  script_summary(english:"Checks the Cisco UCS Central Software web UI version.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure management application running on the remote host is
affected by a remote command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unified Computing System (UCS) Central Software
running on the remote host is prior to 1.3(1c). It is, therefore,
affected by a flaw in its web framework due to improper validation of
user-supplied input. An unauthenticated, remote attacker can exploit
this, via a specially crafted HTTP request, to execute arbitrary
commands on the underlying operating system.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160413-ucs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b1eabfa");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv33856");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2016/Apr/77");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco UCS Central Software version 1.3(1c) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system_central_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");


  script_dependencies("cisco_ucs_central_webui_detect.nbin");
  script_require_keys("installed_sw/Cisco UCS Central WebUI");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:443);

install = get_single_install(app_name:'Cisco UCS Central WebUI', port:port);
version = install['version'];
dir = install['path'];
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Cisco UCS Central Software', install_url);

if (cisco_gen_ver_compare(a:version, b:'1.3(1c)') < 0)
{
  report = '\n  URL               : ' + install_url +
           '\n  Installed version : ' + version +
           '\n  Fixed version     : 1.3(1c) or later' +
           '\n';

  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cisco UCS Central Software', install_url, version);

