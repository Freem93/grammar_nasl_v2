#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55510);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id("CVE-2011-2597", "CVE-2011-2698");
  script_bugtraq_id(48150, 48506, 49071);
  script_osvdb_id(73687, 74731);
  script_xref(name:"Secunia", value:"45086");

  script_name(english:"Wireshark < 1.2.18 / 1.4.8 / 1.6.1 Multiple Denial of Service Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote host has an application that is affected by multiple 
denial of service vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Wireshark is earlier than 1.2.18 / 1.4.8 /
1.6.1 and thus is potentially affected by multiple denial of service 
vulnerabilities:

  - An error in the Lucent / Ascend file parser can be 
    exploited by specially crafted packets to cause high 
    CPU usage. (CVE-2011-2597)

  - An error in the 'elem_cell_id_list' function of the 
    ANSI MAP dissector can be exploited by a specially 
    crafted MAP packet to cause a denial of service 
    condition. (Issue #6044)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2011-09.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2011-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2011-11.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark version 1.2.18 / 1.4.8 / 1.6.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/05");

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

# Check each install.
installs = get_kb_list("SMB/Wireshark/*");
if (isnull(installs)) exit(0, "The 'SMB/Wireshark/*' KB items are missing.");

info = '';
info2 = '';

foreach install (keys(installs))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Wireshark/";
  ver = split(version, sep:".", keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    # Affects 1.2.0 - 1.2.17
    (ver[0] == 1 && ver[1] == 2 && ver[2] < 18)
    ||
    # Affects 1.4.0 - 1.4.7
    (ver[0] == 1 && ver[1] == 4 && ver[2] < 8)
    ||
    # Affects 1.6.0
    (ver[0] == 1 && ver[1] == 6 && ver[2] == 0)
  ) 
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version  +
      '\n  Fixed version     : 1.2.18 / 1.4.8 / 1.6.1\n';
  else
    info2 += 'Version '+ version + ', under '+ installs[install] + '. ';
}

# Report if any were found to be vulnerable
if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 4) s = "s of Wireshark  are";
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
  exit(0, "The following instance(s) of Wireshark are installed and are not vulnerable : "+info2);
