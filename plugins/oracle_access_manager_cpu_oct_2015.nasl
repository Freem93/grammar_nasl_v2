#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86478);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2015-4912");
  script_osvdb_id(129075);

  script_name(english:"Oracle Access Manager Information Disclosure (October 2015 CPU)");
  script_summary(english:"Checks the installed patch/version info.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a Single Sign On (SSO) application installed that
is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Access Manager installed on the remote host is
affected by an information disclosure vulnerability due to an
unspecified flaw in the SSO Engine subcomponent. An unauthenticated,
remote attacker can exploit this to disclose sensitive information.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the October 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/10/20");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_access_manager_installed.nbin");
  script_require_keys("Oracle/OAM/Installed");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("Oracle/OAM/Installed");
installs = get_kb_list_or_exit("Oracle/OAM/*/Version");
product = "Oracle Access Manager";

path = branch(keys(installs));

version = installs[path];
path = path - "Oracle/OAM/" - "/Version";

if (version =~ "^11\.1\.2\.3(\.|$)")
  fixed = "11.1.2.3.4";
else if (version =~ "^11\.1\.2\.2(\.|$)")
  fixed = "11.1.2.2.7";
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
