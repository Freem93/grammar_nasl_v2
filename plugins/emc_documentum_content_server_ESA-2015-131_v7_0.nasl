#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85545);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/20 14:06:57 $");

  script_cve_id("CVE-2015-4536");
  script_bugtraq_id(76412);
  script_osvdb_id(126378);

  script_name(english:"EMC Documentum Content Server Information Disclosure (ESA-2015-131)");
  script_summary(english:"Checks for the Documentum Content Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC Documentum Content Server running on the remote
host is affected an information disclosure vulnerability due to
passwords being stored as plaintext in log files for users with
inline authentication. An authenticated, remote attacker with access
to the log files can exploit this to login using the password of a
different user. Note that this issue is present only when RPC tracing
is enabled.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2015/Aug/att-86/ESA-2015-131.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:documentum_content_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
  make_list("7.0P20"),
  make_list("7.1P18"),
  make_list("7.2P02")
);

documentum_check_and_report(install:install, fixes:fixes, severity:SECURITY_WARNING);
