#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84811);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/17 13:16:56 $");

  script_cve_id("CVE-2015-2593", "CVE-2015-4751");
  script_bugtraq_id(75771, 75831);
  script_osvdb_id(124656, 124657);

  script_name(english:"Oracle Access Manager Multiple Vulnerabilities (July 2015 CPU)");
  script_summary(english:"Checks the installed patch/version info.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a Single Sign On (SSO) application installed that
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Access Manager installed on the remote host is
affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Configuration Service
    subcomponent that allows a remote, authenticated
    attacker to impact confidentiality and integrity.
    (CVE-2015-2593)

  - An unspecified flaw exists in the Authentication Engine
    subcomponent that allows a remote attacker to cause a
    denial of service condition. (CVE-2015-4751)");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18c2a85");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the July 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

if (version =~ "^11\.1\.1\.7(\.|$)")
  fixed = "11.1.1.7.5";
else if (version =~ "^11\.1\.2\.2(\.|$)")
  fixed = "11.1.2.2.6";
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

  security_hole(port:0, extra:report);
}
else security_hole(port:0);
