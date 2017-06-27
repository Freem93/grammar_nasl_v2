#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78692);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/27 19:13:53 $");

  script_cve_id(
    "CVE-2014-6462",
    "CVE-2014-6552",
    "CVE-2014-6553",
    "CVE-2014-6554"
  );
  script_bugtraq_id(70477, 70452, 70483, 70494);
  script_osvdb_id(113275, 113274, 113304, 113273);

  script_name(english:"Oracle Access Manager (October 2014 CPU)");
  script_summary(english:"Checks installed patch/version info.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a Single Sign On application installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Access Manager installed on the remote host is
affected by multiple unspecified vulnerabilities in the Admin Console.
(CVE-2014-6462, CVE-2014-6552, CVE-2014-6553, CVE-2014-6554)");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dcc7b47");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the October 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_access_manager_installed.nbin");
  script_require_keys("Oracle/OAM/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("Oracle/OAM/Installed");
installs = get_kb_list_or_exit("Oracle/OAM/*/Version");
product = "Oracle Access Manager";

path = branch(keys(installs));

version = installs[path];
path = path - "Oracle/OAM/" - "/Version";

if (version =~ "^11\.1\.1\.5(\.|$)")
  fixed = "11.1.1.5.7";
else if (version =~ "^11\.1\.1\.7(\.|$)")
  fixed = "11.1.1.7.2";
else if (version =~ "^11\.1\.2\.1(\.|$)")
  fixed = "11.1.2.1.4";
else if (version =~ "^11\.1\.2\.2(\.|$)")
  fixed = "11.1.2.2.3";
else
  audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);

if (ver_compare(ver:version, fix:fixed, strict:FALSE) >= 0) audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);

if (report_verbosity > 0)
{
  report =
    '\n  The following vulnerable version of ' + product + ' was found' +
    '\n  on the remote host : ' +
    '\n' +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed +
    '\n';

  security_warning(port:0, extra:report);
}
else security_warning(port:0);
