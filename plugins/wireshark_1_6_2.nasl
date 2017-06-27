#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56164);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id(
    "CVE-2011-3266",
    "CVE-2011-3360",
    "CVE-2011-3482",
    "CVE-2011-3483",
    "CVE-2011-3484"
  );
  script_bugtraq_id(
    49377,
    49521,
    49522,
    49524,
    49528
  );
  script_osvdb_id(74732, 75346, 75347, 75348, 75586);
  script_xref(name:"EDB-ID", value:"18125");

  script_name(english:"Wireshark 1.6.x < 1.6.2 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.6.x before 1.6.2.  This
version is affected by the following vulnerabilities :

  - An error exists in IKE dissector that can allow denial
    of service attacks when processing certain malformed
    packets. (CVE-2011-3266)

  - A buffer exception handling vulnerability exists that
    can allow denial of service attacks when processing
    certain malformed packets. (Issue #6135)

  - It may be possible to make Wireshark execute Lua scripts
    using a method similar to DLL hijacking. (Issue #6136)

  - An error exists in OpenSafety dissector that can allow
    denial of service attacks when processing certain
    malformed packets. (Issue #6138)

  - An error exists in CSN.1 dissector that can allow denial
    of service attacks when processing certain malformed
    packets. (Issue #6139)");

  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-12.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-13.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-14.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-15.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.6.2.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark console.lua Pre-Loading Script Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Check each install.
installs = get_kb_list("SMB/Wireshark/*");
if (isnull(installs)) exit(0, "The 'SMB/Wireshark/*' KB items are missing.");

info  = '';
info2 = '';

foreach install(keys(installs))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Wireshark/";

  if (version =~ "^1\.6($|\.[0-1])($|[^0-9])")
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.6.2\n';
  else
    info2 += 'Version ' + version + ', under ' + installs[install] + '. ';
}

# Report if any were found to be vulnerable
if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 4) s = "s of Wireshark are";
    else s = " of Wireshark is";

    report =
      '\n' +
      'The following vulnerable instance' + s + ' installed :\n' +
      '\n' + info;
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
  exit(0);
}
if (info2)
  exit(0, "The following instance(s) of Wireshark are installed and are not vulnerable : " + info2);
