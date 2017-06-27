#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53473);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id("CVE-2011-1590", "CVE-2011-1591", "CVE-2011-1592");
  script_bugtraq_id(47392);
  script_osvdb_id(71846, 71847, 71848);
  script_xref(name:"EDB-ID", value:"17185");
  script_xref(name:"EDB-ID", value:"18145");
  script_xref(name:"Secunia", value:"44172");

  script_name(english:"Wireshark < 1.2.16 / 1.4.5 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.2.x less than 1.2.16 or 1.4.x
less than 1.4.5.  Such versions are affected by the following
vulnerabilities :
  
  - A data type mismatch error exists in the function 
    'dissect_nfs_clientaddr4' in the file 'packet-nfs.c' of
    the NFS dissector and could lead to application crashes
    while decoding 'SETCLIENTID' calls. (5209) 
  
  - A use-after-free error exists in the file 
    'asn1/x509if/x509if.cnf' of the X.509if dissector that
    could lead to application crashes. (5754, 5793) 
  
  - An buffer overflow vulnerability exists in the file
    'packet-dect.c' of the DECT dissector that could allow
    arbitrary code execution. (5836)"
  );
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5209");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5754");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5793");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5836");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-05.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-06.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.5.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.2.16 / 1.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark packet-dect.c Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/18");
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

  if (
    version =~ "^1\.2($|\.[0-9]|\.1[0-5])($|[^0-9])" || 
    version =~ "^1\.4($|\.[0-4])($|[^0-9])"
  )  
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version  +
      '\n  Fixed version     : 1.2.16 / 1.4.5\n';
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
