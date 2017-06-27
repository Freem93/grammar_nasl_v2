#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54846);
  script_version("$Revision: 1.40 $");
  script_cvs_date("$Date: 2016/06/28 18:08:40 $");

  script_name(english:"Sophos Anti-Virus Detection and Status (Mac OS X)");
  script_summary(english:"Checks for Sophos Anti-Virus.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"Sophos Anti-Virus for Mac OS X, a commercial antivirus software
package, is installed on the remote host. However, there is a problem
with the installation; either its services are not running or its
engine and/or virus definitions are out of date.");
  script_set_attribute(attribute:"see_also", value:"http://www.sophos.com/");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:sophos_anti-virus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_sophos_detect.nasl");
  script_require_keys("Antivirus/SophosOSX/installed");

  exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Sophos/Version");
sophos_threat_data = get_kb_item_or_exit("MacOSX/Sophos/ThreatDataVersion");
sophos_engine_version = get_kb_item_or_exit("MacOSX/Sophos/EngineVersion");
sophos_auto_update_running = get_kb_item_or_exit("MacOSX/Sophos/AutoUpdateRunning");
sophos_antivirus_running = get_kb_item_or_exit("MacOSX/Sophos/AntiVirusRunning");
sophos_last_update_date = get_kb_item_or_exit("MacOSX/Sophos/LastUpdateDate");

# Generate report.
info = get_av_info("macosx_sophos");
if (isnull(info)) exit(1, "Failed to get Sophos Anti-Virus info from antivirus.inc.");
# Sophos will sometimes have three levels of detail in a single version, sometimes two. Adapting for both.
match = eregmatch(pattern:"^([0-9]+\.[0-9]+\.[0-9]+).*$", string:version);
# Check if we had a result for three levels of depth.
if (isnull(match) || isnull(info[match[1]]["latest_prod_ver"]))
{
  # Three levels of depth unavailable for this version. Try two!
  match = eregmatch(pattern:"^([0-9]+\.[0-9]+).*$", string:version);
  if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, "Sophos Anti-Virus");
}
prod = match[1];
latest_prod_ver = info[prod]["latest_prod_ver"];
latest_eng_ver = info[prod]["latest_eng_ver"];
latest_sigs_ver = info[prod]["latest_sigs_ver"];
update_date = info["update_date"];

report = '\n';
hole = FALSE;

if (version)
{
  if (latest_prod_ver)
  {
    if (ver_compare(ver:version, fix:latest_prod_ver, strict:FALSE) == -1)
    {
      hole = TRUE;
      report += "Sophos Anti-Virus version :";
      report += '\n  Installed version : ' + version;
      report += '\n  Fixed version     : ' + latest_prod_ver + '\n\n';
    }
    else
    {
      report += "Sophos Anti-Virus version :";
      report += '\n  Installed version : ' + version + '\n\n';
    }
  }
  else
  {
    hole = TRUE;
    report += "Sophos Anti-Virus version :";
    report += '\n  Installed version : ' + version;
    report += '\n' + 'Nessus does not currently have information about Sophos ' + version + '; ';
    report += '\n' + 'it may no longer be supported.\n\n';
  }
}

if (sophos_engine_version)
{
  if (ver_compare(ver:sophos_engine_version, fix:latest_eng_ver, strict:FALSE) == -1)
  {
    hole = TRUE;
    report += "Sophos Anti-Virus engine version :";
    report += '\n  Installed version : ' + sophos_engine_version;
    report += '\n  Latest version    : ' + latest_eng_ver + '\n\n';
  }
  else
  {
    report += "Sophos Anti-Virus engine version :";
    report += '\n  Installed version : ' + sophos_engine_version + '\n\n';
  }
}
else
{
  hole = TRUE;
  report += 'Sophos has not been updated since it was installed.\n';
  report += 'As a result, the remote host might be infected by viruses.\n\n';
}

if (!sophos_antivirus_running)
{
  hole = TRUE;
  report += 'The Sophos Anti-Virus service (SophosAntiVirus) is not running.\n';
  report += 'As a result, the remote host might be infected by viruses.\n\n';
}

if (!sophos_auto_update_running)
{
  hole = TRUE;
  report += 'The Sophos Anti-Virus service (SophosAutoUpdate) is not running.\n';
  report += 'As a result, the system is not receiving virus definition updates.\n\n';
}

if (hole)
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(port:0);
}
else
{
  # nb: antivirus.nasl uses this in its own report.
  set_kb_item (name:"Antivirus/SophosOSX/description", value:report);
  exit(0, "Detected Sophos Anti-Virus with no known issues to report.");
}
