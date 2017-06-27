#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76428);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2014-0224");
  script_bugtraq_id(67899);
  script_osvdb_id(107729);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"IBM General Parallel File System OpenSSL Security Bypass (Windows)");
  script_summary(english:"Checks the local version of GPFS.");

  script_set_attribute(attribute:"synopsis", value:
"A clustered file system on the remote host is affected by a security
vulnerability.");
  script_set_attribute(attribute:"description", value:
"A version of IBM General Parallel File System (GPFS) 3.5.0.11 or later
but prior to 3.5.0.18 is installed on the remote host. It is,
therefore, affected by an unspecified error that could allow an
attacker to cause usage of weak keying material, leading to simplified
man-in-the-middle attacks.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=isg3T1020948");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0224");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to GPFS 3.5.0.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/09");

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

fix = "3.5.0.18";

# Affected :
# 3.5.0.11 >= version < 3.5.0.18
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
    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
