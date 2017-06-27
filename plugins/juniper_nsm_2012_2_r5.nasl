#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71023);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:02:52 $");

  script_cve_id(
    "CVE-2012-0022",
    "CVE-2012-5568",
    "CVE-2012-5885",
    "CVE-2012-5886",
    "CVE-2012-5887"
  );
  script_bugtraq_id(51447, 56403, 56686);
  script_osvdb_id(78573, 87223, 87579, 87580, 88285);

  script_name(english:"Juniper NSM Servers < 2012.2R5 Multiple Vulnerabilities");
  script_summary(english:"Checks versions of NSM servers");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the version of one or more Juniper NSM servers running on
the remote host, it is potentially affected by the following
vulnerabilities related to the included Apache Tomcat version :

  - An error exists related to handling requests containing
    several parameters that could allow denial of service
    attacks. (CVE-2012-0022)

  - An error exists related to handling partial HTTP
    requests that could allow denial of service attacks.
    (CVE-2012-5568)

  - Errors exist related to handling DIGEST authentication
    that could allow security mechanisms to be bypassed.
    (CVE-2012-5885, CVE-2012-5886, CVE-2012-5887)"
  );
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10600");
  script_set_attribute(attribute:"see_also", value:"http://www.juniper.net/support/downloads/?p=nsm#sw");
  script_set_attribute(attribute:"solution", value:"Upgrade to NSM version 2012.2R5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:netscreen-security_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("juniper_nsm_gui_svr_detect.nasl", "juniper_nsm_servers_installed.nasl");
  script_require_keys("Juniper_NSM_VerDetected");
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

kb_base = "Host/NSM/";

get_kb_item_or_exit("Juniper_NSM_VerDetected");

kb_list = make_list();

temp = get_kb_list("Juniper_NSM_GuiSvr/*/build");

if (!isnull(temp) && max_index(keys(temp)) > 0)
  kb_list = make_list(kb_list, keys(temp));

temp = get_kb_list("Host/NSM/*/build");
if (!isnull(temp) && max_index(keys(temp)) > 0)
  kb_list = make_list(kb_list, keys(temp));

if (isnull(kb_list)) audit(AUDIT_NOT_INST, "Juniper NSM Servers");

report = '';

entry = branch(kb_list);

port = 0;
kb_base = '';

if ("Juniper_NSM_GuiSvr" >< entry)
{
  port = entry - "Juniper_NSM_GuiSvr/" - "/build";
  kb_base = "Juniper_NSM_GuiSvr/" + port + "/";

  report_str1 = "Remote GUI server version : ";
}
else
{
  kb_base = entry - "build";
  if ("guiSvr" >< kb_base)
    report_str1 = "Local GUI server version    : ";
  else
    report_str1 = "Local device server version : ";
}

build = get_kb_item_or_exit(entry);
version = get_kb_item_or_exit(kb_base + 'version');

disp_version = version + " (" + build + ")";

# affected per advisory :
#   2010.3
#   2011.4
#   2012.1
#   2012.2
# fix :
#   NSM version 2012.2R5 or later
item = eregmatch(pattern:"^([0-9.R]+)", string:version);
if (!isnull(item))
{
  if (
    item[1] =~ "^2010\.3($|[^0-9])"
    ||
    item[1] =~ "^2011\.4($|[^0-9])"
    ||
    item[1] =~ "^2012\.1($|[^0-9])"
    ||
    item[1] =~ "^2012\.2($|R[1-4]$)"
  )
  {
    report += '\n  ' + report_str1 + disp_version +
              '\n  Fixed version               : 2012.2R5 (LGB18z1e51)' + '\n';
  }
}

if (report == '') audit(AUDIT_INST_VER_NOT_VULN, "Juniper NSM GUI Server or Device Server");

if (report_verbosity > 0) security_warning(extra:report, port:port);
else security_warning(port);
