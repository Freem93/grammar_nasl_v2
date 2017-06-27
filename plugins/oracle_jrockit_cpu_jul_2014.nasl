#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76883);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/28 19:00:57 $");

  script_cve_id("CVE-2014-4244", "CVE-2014-4263");
  script_bugtraq_id(68624, 68636);
  script_osvdb_id(109141, 109142);

  script_name(english:"Oracle JRockit R27 < R27.8.3.9 / R28 < R28.3.3.10 Multiple Vulnerabilities (July 2014 CPU)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Oracle JRockit that is affected by
multiple vulnerabilities that could allow a remote user to affect the
confidentiality of the system via :

  - A design flaw in the RSA 'blinding' security component
    of the 'RASCore' class. By performing operations
    requiring the use of private keys and measuring timing
    differences, an attacker may be able to disclose
    information about the keys used.
    (CVE-2014-4244).

  - A design flaw in the 'validateDHPublicKey' function of
    the 'KeyUtil' class. A remote attacker may be able to
    recover a key. (CVE-2014-4263).");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de2f8eb");
  script_set_attribute(attribute:"solution", value:"Upgrade to version R27.8.3.9 / R28.3.3.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_jrockit_installed.nasl");
  script_require_keys("installed_sw/Oracle JRockit");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app     = "Oracle JRockit";
get_install_count(app_name:app, exit_if_zero:TRUE);
install = get_single_install(app_name:app);
ver     = install['version'];
type    = install['type'];
path    = install['path'];

# 26 and below may not be supported, may not be affected --
# it's not listed as affected so we do not check it.
if (ver_compare(ver:ver, fix:"27", strict:FALSE) < 0) audit(AUDIT_INST_VER_NOT_VULN, app);

vulnerable = FALSE;
# Determine if the install is vulnerable, splitting the cases into
# v27 and below, and v28 above.
if (ver_compare(ver:ver, fix:"28", strict:FALSE) < 0)
{
  fix = "27.8.3.9"; # Very specific fix pulled from the patch
  # Are we in the vulnerable range? v >= 27.8.2 && v < 27.8.3
  if (
    ver_compare(ver:ver,fix:"27.8.2",strict:FALSE) >= 0 &&
    ver_compare(ver:ver,fix:"27.8.3",strict:FALSE) < 0
  ) vulnerable = TRUE;
}
else
{
  fix = "28.3.3.10"; # Very specific fix pulled from the patch
  # Are we in the vulnerable range? v >= 28.3.2 && v < 28.3.3
  if (
    ver_compare(ver:ver,fix:"28.3.2",strict:FALSE) >= 0 &&
    ver_compare(ver:ver,fix:"28.3.3",strict:FALSE) < 0
  ) vulnerable = TRUE;
}

# Weren't in vulnerable range
if (!vulnerable) audit(AUDIT_INST_VER_NOT_VULN, app);

# The DLL we're looking at is a level deeper in the JDK, since it
# keeps a subset of the JRE in a subdirectory.
if (type == "JDK")  path += "\jre";

path += "\bin\jrockit\jvm.dll";

report =
  '\n  Type              : ' + type +
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
