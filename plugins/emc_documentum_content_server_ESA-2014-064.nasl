#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77634);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/11 16:38:56 $");

  script_cve_id("CVE-2014-2513", "CVE-2014-2514");
  script_bugtraq_id(68435, 68436);
  script_osvdb_id(108801, 108802);

  script_name(english:"EMC Documentum Content Server Multiple Vulnerabilities (ESA-2014-064)");
  script_summary(english:"Checks for Documentum Content Server.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of EMC Documentum Content Server
that is affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists due to
    improper authorization checks. A remote, authenticated
    attacker can exploit this vulnerability to execute
    arbitrary code via a custom script.
    (CVE-2014-2513)

  - A remote code execution vulnerability exists due to
    improper authorization checks. A remote, authenticated
    attacker can exploit this vulnerability to execute
    arbitrary code via save RPC commands.
    (CVE-2014-2514)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Jul/att-23/ESA-2014-064.txt");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:documentum_content_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("emc_documentum_content_server_installed.nbin");
  script_require_keys("installed_sw/EMC Documentum Content Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("emc_documentum.inc");

app_name = DOC_APP_NAME;
get_install_count(app_name:app_name, exit_if_zero:TRUE);
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

fixes = make_nested_list(
  make_list("7.1P06"),
  make_list("7.0P15"),
  make_list("6.7SP2P15"),
  make_list("6.7SP1P28", DOC_NO_MIN)
);

documentum_check_and_report(install:install, fixes:fixes, severity:SECURITY_HOLE);
