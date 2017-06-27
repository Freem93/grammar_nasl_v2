#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49978);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/15 19:41:09 $");

  script_cve_id("CVE-2010-3445");
  script_bugtraq_id(43197);
  script_osvdb_id(68129);
  script_xref(name:"Secunia", value:"41535");

  script_name(english:"Wireshark < 1.2.12 / 1.4.1 ASN.1 BER Dissector Denial of Service");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is vulnerable to
a denial of service attack."
  );
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.2.x less than 1.2.12 or 1.4.x
less than 1.4.1.  Such versions are affected by a denial of service
vulnerability.  The ASN.1 BER dissector contains a flaw that can allow
a stack overflow that in turn can cause the application to crash."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2010/Sep/87"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.wireshark.org/security/wnpa-sec-2010-11.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.wireshark.org/security/wnpa-sec-2010-12.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark version 1.2.12 / 1.4.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/14");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

  if (
    version =~ "^1\.2($|\.[0-9]|\.1[01])($|[^0-9])" || 
    version =~ "^1\.4($|\.0)($|[^0-9])"
  )  
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version  +
      '\n  Fixed version     : 1.2.12 / 1.4.1\n';
  else
    info2 += 'Version '+ version + ', under '+ installs[install] + '. ';
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
  exit(0, "The following instance(s) of Wireshark are installed and are not vulnerable : "+info2);
