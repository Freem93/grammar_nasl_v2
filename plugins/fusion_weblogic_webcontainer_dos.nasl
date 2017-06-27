#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57794);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/06/02 20:36:50 $");

  script_cve_id("CVE-2011-3566");
  script_bugtraq_id(51469);
  script_osvdb_id(78400);

  script_name(english:"Oracle Fusion Middleware WebLogic Component DoS");
  script_summary(english:"Checks version of Oracle WebLogic Component");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application server installed that contains
an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the WebLogic component on Oracle Middleware installed
on the remote host is affected by an unspecified vulnerability related
to the Web Container affecting availability. Successful exploitation
of this vulnerability could cause a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9a69d65");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11da589e");
  script_set_attribute(attribute:"solution", value:
"See the Oracle advisory for information on obtaining and applying bug
fix patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_weblogic_server_installed.nbin");
  script_require_keys("Oracle/WLS/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("oracle_rdbms_cpu_func.inc");

get_kb_item_or_exit("Oracle/WLS/Installed");
app_name = "Oracle WebLogic Server";
report = "";
affected = 0;
not_affected = make_list();

# Get installs.
installs = make_list(get_kb_list("Oracle/WLS/*/install"));

# Get patches.
ohomes = make_list();
q = query_scratchpad("SELECT path FROM oracle_homes");
if (isnull(q)) exit(1, 'Unable to obtain Oracle Homes');
foreach ohome (q)
{
  ohomes = make_list(ohomes, ohome['path']);
}

patches = find_patches_in_ohomes(ohomes:ohomes);

if(!isnull(patches))
{
  # Verify that each install is patched.
  foreach install (installs)
  {
    install = split(install, sep:',', keep:FALSE);
    ohome = install[0];
    subdir = install[1];
    version = install[2];
    patched = FALSE;
    fix = NULL;
    fix_ver = NULL;

    # individual security patches
    if      (version =~ "^9\.2\.4(\.0)*$") fix = "TW4A";
    else if (version =~ "^10\.0\.1(\.0)*$") fix = "96PR";
    else if (version =~ "^10\.0\.2(\.0)*$") fix = "2DIK";
    else if (version =~ "^10\.3\.0(\.0)*$") fix = "JAE6";
    else if (version =~ "^10\.3\.2(\.0)*?$") fix = "AVJP";
    else if (version =~ "^10\.3\.3(\.0)*?$") fix = "1FKM";

    # patch sets
    else if (version =~ "^10\.3\.5\.")
    {
      fix_ver = "10.3.5.0.2";
      fix = "USGW";
    }
    else if (version =~ "^10\.3\.4\.")
    {
      fix_ver = "10.3.4.0.4";
      fix = "XZNF";
    }
    else not_affected = make_list(not_affected, version);

    if (isnull(fix)) continue;

    # patch set check
    if(!isnull(fix_ver))
    {
      if(ver_compare(ver:version, fix:fix_ver, strict:FALSE) >= 0)
        patched = TRUE;
    }
    # security patch check
    else
    {
      # Check for patch.
      foreach patch (keys(patches[ohome]))
      {
        if (patch == fix)
        {
          patched = TRUE;
          break;
        }
      }
    }

    if (!patched)
    {
      report +=
        '\n  Oracle Home    : ' + ohome +
        '\n  Install path   : ' + subdir +
        '\n  Version        : ' + version +
        '\n  Required patch : ' + fix +
        '\n';

      affected++;
    }
    else not_affected = make_list(not_affected, version);
  }
}

if (affected)
{
  port = 0;

  if (report_verbosity > 0)
  {
    report = affected + ' of ' + max_index(installs) + ' installs affected :\n' + report;
    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, not_affected);
