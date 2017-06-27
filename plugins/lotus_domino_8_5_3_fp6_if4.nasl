#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83115);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/29 13:26:12 $");

  script_cve_id("CVE-2015-0135");
  script_bugtraq_id(74194);
  script_osvdb_id(120888);

  script_name(english:"IBM Domino 8.5.x < 8.5.3 Fix Pack 6 Interim Fix 4 GIF Code Execution (credentialed check)");
  script_summary(english:"Checks the version of IBM Domino.");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Domino (formerly IBM Lotus Domino) installed on the
remote host is 8.5.x prior to 8.5.3 Fix Pack 6 (FP6) Interim Fix 4
(IF4). It is, therefore, potentially affected by an integer truncation
error when processing GIF files. A remote attacker, using a crafted
GIF file, could exploit this to execute arbitrary code or cause a
denial of service.");
  # Advisory
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21701647");
  # Patch
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21663874");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 IF4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("lotus_domino_installed.nasl");
  script_require_keys("installed_sw/IBM Domino", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Paranoid as special fixes are unknown to us
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app        = "IBM Domino";
fixed_ver  = "8.5.36.14304";

installs   = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
domino_ver = installs['version'];
path       = installs['path'];

if (domino_ver !~ "^8\.5($|[^0-9])") audit(AUDIT_NOT_INST, app + " 8.5.x");

if (ver_compare(ver:domino_ver, fix:fixed_ver, strict:FALSE) == -1)
{
  port = get_kb_item('SMB/transport');
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed Version : ' + domino_ver +
      '\n  Fixed Version     : ' + fixed_ver  +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, domino_ver, path);
