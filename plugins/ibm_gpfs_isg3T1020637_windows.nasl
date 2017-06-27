#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76766);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/15 18:43:50 $");

  script_cve_id("CVE-2014-1692");
  script_bugtraq_id(65230);
  script_osvdb_id(102611);

  script_name(english:"IBM General Parallel File System OpenSSH Memory Corruption");
  script_summary(english:"Checks the local version of GPFS.");

  script_set_attribute(attribute:"synopsis", value:
"A clustered file system on the remote host is affected by a memory
corruption vulnerability related to OpenSSH.");
  script_set_attribute(attribute:"description", value:
"A version of IBM General Parallel File System (GPFS) that is 3.5.0.11
or later but prior to 3.5.0.19 is installed on the remote host. It is,
therefore, affected by a memory corruption issue in the bundled
version of OpenSSH. The issue exists due to a failure to initialize
certain data structures when makefile.inc is modified to enable the
J-PAKE protocol. An unauthenticated, remote attacker can exploit this
to corrupt memory, resulting in a denial of service condition and
potentially the execution of arbitrary code.");
  # https://www.ibm.com/blogs/psirt/ibm-security-bulletin-vulnerability-in-open-secure-shell-for-gpfs-v3-5-on-windows-cve-2014-1692/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74c0bc32");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM GPFS version 3.5.0.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:general_parallel_file_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

if (version !~ "^(\d+\.){3,}\d+$") audit(AUDIT_VER_NOT_GRANULAR, app_name, version);
if (version !~ "^3\.5\.") audit(AUDIT_NOT_INST, app_name + " 3.5.x");

fix = "3.5.0.19";

# Affected :
# 3.5.0.11 >= version < 3.5.0.19
if (
  ver_compare(ver:version, fix:'3.5.0.11', strict:FALSE) >= 0
  &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
