#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77864);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/25 21:10:52 $");

  script_cve_id("CVE-2014-4621", "CVE-2014-4622");
  script_bugtraq_id(69817, 69819);
  script_osvdb_id(111558, 111559);

  script_name(english:"EMC Documentum Content Server Multiple Privilege Escalation Vulnerabilities (ESA-2014-091)");
  script_summary(english:"Checks for Documentum Content Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple privilege escalation
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of EMC Documentum Content Server
that is affected by multiple vulnerabilities :

  - A privilege escalation vulnerability exists due to
    improper handling of system objects that allows a user
    to escalate their privileges to super-user status.
    (CVE-2014-4621)

  - A privilege escalation vulnerability exists due to
    improper handling of subgroups in the 'dm_superusers'
    group and other privileged groups. A user with sysadmin
    privileges can escalate their privileges to super-user
    status.  (CVE-2014-4622)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Sep/att-92/ESA-2014-091.txt");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/25");

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
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

fixes = make_nested_list(
  make_list("7.1P08"),
  make_list("7.0P15" + DOC_HOTFIX),
  make_list("6.7SP2P17", DOC_NO_MIN)
);

documentum_check_and_report(install:install, fixes:fixes, severity:SECURITY_HOLE);
