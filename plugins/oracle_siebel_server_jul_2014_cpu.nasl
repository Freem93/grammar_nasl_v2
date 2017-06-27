#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76576);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/08 22:17:48 $");

  script_cve_id(
    "CVE-2014-2485",
    "CVE-2014-2491",
    "CVE-2014-4205",
    "CVE-2014-4230",
    "CVE-2014-4231",
    "CVE-2014-4250"
  );
  script_bugtraq_id(
    68604,
    68614,
    68619,
    68625,
    68630,
    68635
  );
  script_osvdb_id(
    109118,
    109119,
    109120,
    109121,
    109122,
    109123
  );

  script_name(english:"Oracle Siebel Multiple Vulnerabilities (July 2014 CPU)");
  script_summary(english:"Checks the version of Siebel Server.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Siebel install is affected by multiple unspecified
vulnerabilities.");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de2f8eb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2014 Oracle Critical 
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:siebel_crm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_siebel_server_installed.nbin");
  script_require_keys("Oracle/siebel_server/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("Oracle/siebel_server/Installed");
app_name = "Oracle Siebel Server";

report = "";
affected = 0;
not_affected = make_list();

# Get installs.
installs = get_kb_list("Oracle/siebel_server/*/Version");

# Verify that each install is patched.
foreach install (keys(installs))
{
  version = installs[install];
  subdir = install - 'Oracle/siebel_server/' - '/Version';

  patched = FALSE;
  fix = NULL;

  if (version =~ "^8\.1\.1\.")
  {
    fix = "811119";
    fix_ver = "8.1.1.11.9";
  }
  else if (version =~ "^8\.2\.2\.")
  {
    fix = "82249";
    fix_ver = "8.2.2.4.9";
  }

  else not_affected = make_list(not_affected, version);
  if (isnull(fix)) continue;

  # patch set check
  if (!isnull(fix_ver))
  {
    if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) >= 0)
      patched = TRUE;
  }

  if (!patched)
  {
    if (!isnull(subdir))
      report += '\n  Install path   : ' + subdir;

    report +=
      '\n  Installed version : ' + version +
      '\n  Required patch    : ' + fix +
      '\n';

    affected++;
  }
  else not_affected = make_list(not_affected, version);
}

if (affected)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report = affected + ' of ' + max_index(keys(installs)) + ' installs affected :\n' + report;
    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, not_affected);
