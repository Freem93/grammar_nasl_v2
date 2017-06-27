#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72508);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/03/21 21:52:40 $");

  script_cve_id("CVE-2014-0834");
  script_bugtraq_id(65297);
  script_osvdb_id(102765);

  script_name(english:"IBM General Parallel File System 3.4 < 3.4.0.27 / 3.5 < 3.5.0.16 DoS (Windows)");
  script_summary(english:"Checks local version of GPFS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A clustered file system on the remote host is affected by a denial of
service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A version of IBM General Parallel File System (GPFS) prior to 3.4.0.27
/ 3.5.0.16 is installed on the remote host.  It is, therefore, affected
by a denial of service vulnerability.  An authenticated, non-root
attacker can exploit this vulnerability by passing certain arguments to
'setuid' commands, potentially causing the GPFS daemon to crash."
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_general_parallel_file_system_denial_of_service_vulnerability_cve_2014_0834?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a45ae87");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=isg3T1020542");
  script_set_attribute(attribute:"solution", value:"Upgrade to GPFS 3.4.0.27 / 3.5.0.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:general_parallel_file_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ibm_gpfs_installed.nbin");
  script_require_keys("SMB/ibm_gpfs/path", "SMB/ibm_gpfs/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "IBM General Parallel File System";
version = get_kb_item_or_exit("SMB/ibm_gpfs/version");
path = get_kb_item_or_exit("SMB/ibm_gpfs/path");
fix = NULL;

if (version !~ "^(\d+\.){3,}\d+$") audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

if (version =~ "^3\.4\..*$") fix = "3.4.0.27";
else if (version =~ "^3\.5\..*$") fix = "3.5.0.16";

if (fix && (ver_compare(ver:version, fix:fix, strict:FALSE) == -1))
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
