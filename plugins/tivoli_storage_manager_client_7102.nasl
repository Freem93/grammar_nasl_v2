#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77529);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/03/20 18:55:12 $");

  script_cve_id("CVE-2013-6335");
  script_bugtraq_id(69372);
  script_osvdb_id(109998);

  script_name(english:"IBM Tivoli Storage Manager Client Metadata Local File Access Information Disclosure");
  script_summary(english:"Checks the version of IBM Tivoli Storage Manager Client.");

  script_set_attribute(attribute:"synopsis", value:
"A client application installed on the remote Linux host is affected by
an unauthorized file access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Tivoli Storage Manager Client installed on the remote
Linux host is affected by an unauthorized file access vulnerability. A
flaw exists with the Tivoli Backup-Archive client when restoring Space
Management file metadata. A local attacker can exploit this flaw to
gain access to the restored files.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21680453");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tivoli Storage Manager Client 6.2.5.3 / 6.3.2 / 6.4.2 /
7.1.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("tivoli_storage_manager_client_installed_linux.nbin");
  script_exclude_keys("SMB/Registry/Enumerated");
  script_require_keys("installed_sw/Tivoli Storage Manager Client");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Make sure the host is not Windows
if (get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Linux", "Windows");

app = 'Tivoli Storage Manager Client';
get_install_count(app_name:app, exit_if_zero:TRUE);

# Space Management is not affected, but is required for the BA client to be vulnerable
sm_installed = FALSE;

editions = get_kb_list_or_exit("installed_sw/"+app+"/*/Edition");

foreach edition (editions)
{
  if (edition == "Tivoli Storage Manager Client for Space Management")
  {
    sm_installed = TRUE;
    break;
  }
}

if (!sm_installed) audit(AUDIT_INST_VER_NOT_VULN, app);


install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
package = install['Package'];
edition = install['Edition'];

if (edition == "Tivoli Storage Manager Backup-Archive Client")
{
  fix = NULL;
  
  if (version =~ '^5\\.[45]\\.' || version =~ '^6\\.1\\.')
    fix = "Please refer to the vendor for a fix.";
  else if (version =~ '^6\\.2\\.' && ver_compare(ver:version, fix:'6.2.5.3', strict:FALSE) < 0) fix = '6.2.5.3';
  else if (version =~ '^6\\.3\\.' && ver_compare(ver:version, fix:'6.3.2', strict:FALSE) < 0) fix = '6.3.2';
  else if (version =~ '^6\\.4\\.' && ver_compare(ver:version, fix:'6.4.2', strict:FALSE) < 0) fix = '6.4.2';
  else if (version =~ '^7\\.1\\.' && ver_compare(ver:version, fix:'7.1.0.3', strict:FALSE) < 0) fix = '7.1.0.3';
  
  if (isnull(fix)) audit(AUDIT_PACKAGE_NOT_AFFECTED, package);
  
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix     +
      '\n  Package           : ' + package +
      '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
}
