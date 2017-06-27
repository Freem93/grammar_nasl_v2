#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56689);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/03/21 16:56:11 $");

  script_cve_id("CVE-2011-4101", "CVE-2011-4102");
  script_bugtraq_id(50481, 50486);
  script_osvdb_id(76769, 76770);

  script_name(english:"Wireshark 1.4.x < 1.4.10 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.4.x before 1.4.10.  This
version is affected by the following vulnerabilities :

  - An error exists in the Infiniband dissector that can
    allow a NULL pointer to be dereferenced when processing
    certain malformed packets. (CVE-2011-4101)

  - A buffer overflow exists in the ERF file reader and can
    be triggered when processing certain malformed packets.
    (CVE-2011-4102)");

  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-18.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-19.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.10.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.4.10 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

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

  if (version =~ "^1\.4($|\.[0-9])($|[^0-9])")
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.4.10\n';
  else
    info2 += 'Version ' + version + ', under ' + installs[install] + '. ';
}

# Report if any were found to be vulnerable.
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
if (info2) exit(0, "The following installed instance(s) of Wireshark are not affected : " + info2);
