#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74253);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/04 19:55:21 $");

  script_cve_id("CVE-2014-2607");
  script_bugtraq_id(67570);
  script_osvdb_id(107247);
  script_xref(name:"HP", value:"emr_na-c04296442");
  script_xref(name:"IAVB", value:"2014-B-0064");
  script_xref(name:"HP", value:"HPSBMU03042");
  script_xref(name:"HP", value:"SSRT101575");

  script_name(english:"HP Operations Manager i (OMi) 9.1 / 9.2 RCE");
  script_summary(english:"Checks HP Operations Manager i version / build.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an operations management application installed
that is affected by an unspecified code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The HP Operations Manager i (OMi) installed on the remote host is
version 9.1 or 9.2. It is, therefore, affected by an unspecified code
execution vulnerability that allows an authenticated, remote attacker
to execute arbitrary code by leveraging the OMi operator role.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04296442
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87d5d6f0");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532177/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Apply the vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:operations_manager_i");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("hp_operations_manager_i_installed.nbin");
  script_require_keys("SMB/HP Operations Manager i/Version", "SMB/HP Operations Manager i/Build", "SMB/HP Operations Manager i/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/HP Operations Manager i/Version");
build = get_kb_item_or_exit("SMB/HP Operations Manager i/Build");
path = get_kb_item_or_exit("SMB/HP Operations Manager i/Path");

build_parts = split(build, sep:'.', keep:FALSE);
disp_version = version + ' Build ' + version + '.' + build_parts[0];

fixed_version = '';
if (version =~ '^09\\.1[0-3]($|\\.)' && int(build_parts[0]) < 739)
  fixed_version = '09.13 Build 09.13.739';
else if (version =~ '^09\\.2[0-4]($|\\.)' && int(build_parts[0]) < 51)
  fixed_version = '09.24 Build 09.24.051';
else 
  audit(AUDIT_INST_PATH_NOT_VULN, 'HP Operations Manager i', disp_version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + disp_version +
    '\n  Fixed version     : ' + fixed_version + 
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
