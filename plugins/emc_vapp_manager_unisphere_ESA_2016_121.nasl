#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94514);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id(
    "CVE-2016-6645",
    "CVE-2016-6646"
  );
  script_bugtraq_id(93343);
  script_osvdb_id(
    145151,
    145152,
    145691,
    145692
  );
  script_xref(name:"IAVB", value:"2016-B-0147");

  script_name(english:"EMC Unisphere for VMAX Virtual Appliance 8.x < 8.3.0 RCE");
  script_summary(english:"Checks the version of EMC vApp Manager for Unisphere.");

  script_set_attribute(attribute:"synopsis", value:
"The remote virtual appliance is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC Unisphere for VMAX Virtual Appliance running on the
remote host is 8.x prior to 8.3.0. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple flaws exist in the web interface related to the
    GeneralCmdRequest, PersistantDataRequest, and
    GetCommandExecRequest classes. An authenticated, remote
    attacker can exploit these, via a specially crafted
    request, to execute arbitrary commands with root
    privileges. (CVE-2016-6645)

  - Multiple flaws exist in the web interface related to the
    GetSymmCmdRequest and RemoteServiceHandler classes. An
    unauthenticated, remote attacker can exploit these, via
    a specially crafted request, to execute arbitrary
    commands with root privileges. (CVE-2016-6646)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2016/Oct/att-7/ESA-2016-121.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Unisphere for VMAX Virtual Appliance version 8.3.0 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:unisphere");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("emc_vapp_manager_detect.nbin");
  script_require_keys("Host/EMC/Unisphere for VMAX Virtual Appliance/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http_func.inc");

appliance = "Unisphere for VMAX Virtual Appliance";
version   = get_kb_item_or_exit("Host/EMC/"+appliance+"/Version");

fix    = '8.3.0';
minver = '8.0.0';

ret = ver_compare(ver:version, fix:fix, minver:minver, strict:FALSE);
if (isnull(ret) || ret >= 0)
  audit(AUDIT_OS_RELEASE_NOT, appliance, version);

report_items = make_array(
  "Appliance version", version,
  "Fixed version", fix
);

ordered_fields = make_list("Appliance version", "Fixed version");

report = report_items_str(report_items:report_items, ordered_fields:ordered_fields);

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
