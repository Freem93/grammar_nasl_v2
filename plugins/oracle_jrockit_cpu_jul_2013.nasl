#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69305);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/08 22:17:48 $");

  script_cve_id("CVE-2013-2461");
  script_bugtraq_id(60645);
  script_osvdb_id(94350);

  script_name(english:"Oracle JRockit R27 < R27.7.6 / R28 < R28.2.8 Unspecified Vulnerability (July 2013 CPU)");
  script_summary(english:"Checks version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
potentially affected by an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Oracle JRockit that is reportedly
affected by an unspecified vulnerability.");
  # http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d601a70e");
  script_set_attribute(attribute:"solution", value:"Update to version R27.7.6 / R28.2.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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

if (ver_compare(ver:ver, fix:"28", strict:FALSE) < 0)
{
  compare = "27.7.6";
  fix     = "27.7.6.8";
}
else
{
  compare = "28.2.8";
  fix     = "28.2.8.10";
}

if (ver_compare(ver:ver, fix:compare, strict:FALSE) >= 0) audit(AUDIT_INST_VER_NOT_VULN, app);

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

if (report_verbosity > 0) security_hole(port:port, extra:report);
else security_hole(port);
