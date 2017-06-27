#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(52502);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/01/13 15:34:52 $");

  script_cve_id(
    "CVE-2011-0538",
    "CVE-2011-0713",
    "CVE-2011-1138",
    "CVE-2011-1139",
    "CVE-2011-1140",
    "CVE-2011-1141",
    "CVE-2011-1142",
    "CVE-2011-1143"
  );
  script_bugtraq_id(46167, 46416, 46626, 46636, 46796, 46945);
  script_osvdb_id(
    71548,
    71549,
    71550,
    71551,
    71552,
    71553,
    71554,
    71555,
    71556
  );
  script_xref(name:"Secunia", value:"42767");

  script_name(english:"Wireshark < 1.2.15 / 1.4.4 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.0.x or 1.2.x less than 1.2.15
or 1.4.x less than 1.4.4.  Such versions are affected by the following
vulnerabilities :

  - The BER dissector may loop indefinitely. (Bug #1516)

  - A crash can occur in the NTLMSSP dissector. (Bug #5157)

  - An error exists in the processing of pcap-ng files
    that causes the application to free an uninitialized
    pointer. (Bug #5652) 

  - An error exists in the processing of packets having 
    large length in a pcap-ng file. This can result in 
    application crashes. (Bug #5661) 

  - A stack overflow vulnerability exists in the LDAP and
    SMB dissectors. (Bug #5717) 

  - An error exists in the processing of malformed 6LoWPAN
    packets. This affects only 32-bit platforms and can 
    result in application crashes. (Bug #5722) 

  - An error exists in the processing of large LDAP filter
    strings that cause the application to consume excessive 
    amounts of memory. (Bug #5732)"
  );
  script_set_attribute(attribute:"see_also", value:"http://anonsvn.wireshark.org/viewvc?view=rev&revision=35953");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5652");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5661");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5717");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5722");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5732");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-03.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-04.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.15.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.4.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.2.15 / 1.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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
    version =~ "^1\.0($|\.)" || 
    version =~ "^1\.2($|\.[0-9]|\.1[0-4])($|[^0-9])" || 
    version =~ "^1\.4($|\.[0-3])($|[^0-9])"
  )  
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version  +
      '\n  Fixed version     : 1.2.15 / 1.4.4\n';
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
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
if (info2)
  exit(0, "The following instance(s) of Wireshark are installed and are not vulnerable : "+info2);
