#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62478);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/05/22 10:43:52 $");

  script_cve_id(
    "CVE-2012-3548",
    "CVE-2012-5237",
    "CVE-2012-5238",
    "CVE-2012-5240"
  );
  script_bugtraq_id(55284, 55754);
  script_osvdb_id(85092, 85883, 85884, 85885);

  script_name(english:"Wireshark 1.8.x < 1.8.3 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.8 is earlier than 1.8.3.  It thus
is affected by the following vulnerabilities :

  - A malformed packet can cause the 'DRDA' and 'HSRP'
    dissectors to enter an infinite loop, thereby consuming
    excessive CPU resources. (CVE-2012-3548, CVE-2012-5237)

  - A malformed packet can cause the 'PPP' dissector to
    crash the application. (CVE-2012-5238)

  - A malformed packet can trigger a buffer overflow in the
    'LDP' dissector, which results in an application crash.
    (CVE-2012-5240)");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-26.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-27.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-28.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-29.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.3.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.8.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Check each install.
installs = get_kb_list_or_exit("SMB/Wireshark/*");

info  = '';
info2 = '';

foreach install(keys(installs))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Wireshark/";

  if (version =~ "^1\.8\.[0-2]($|[^0-9])")
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.8.3\n';
  else
    info2 += 'Version ' + version + ', under ' + installs[install] + ' ';
}

# Remove trailing space on info2
if (strlen(info2) > 1)
  info2 = substr(info2, 0, strlen(info2) -2);

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
if (info2) exit(0, "The following installed instance(s) of Wireshark are not affected : " + info2 + ".");
