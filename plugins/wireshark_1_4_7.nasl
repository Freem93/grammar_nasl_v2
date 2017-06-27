#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54942);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/11/27 15:42:54 $");

  script_cve_id(
    "CVE-2011-1956",
    "CVE-2011-1957",
    "CVE-2011-1958",
    "CVE-2011-1959",
    "CVE-2011-2174",
    "CVE-2011-2175"
  );
  script_bugtraq_id(48066);
  script_osvdb_id(
    72974,
    72975,
    72976,
    72977,
    72978,
    72979
  );
  script_xref(name:"Secunia", value:"44449");

  script_name(english:"Wireshark < 1.2.17 / 1.4.7 Multiple DoS Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.2.x less than 1.2.17 or 1.4.x
less than 1.4.7.  As such, it is affected by the following
vulnerabilities :
  
  - An error exists in DICOM dissector that can allow denial
    of service attacks when processing certain malformed
    packets. (Issue #5876)

  - An error exists in the handling of corrupted snoop
    files that can cause application crashes. (Issue #5912)

  - An error exists in the handling of compressed capture
    data that can cause application crashes. (Issue #5908)

  - An error exists in the handling of 'Visual Networks'
    files that can cause application crashes. (Issue #5934)

  - An error exists in the 'desegment_tcp()' function in the
    file 'epan/dissectors/packet-tcp.c' that can allow a NULL
    pointer to be dereferenced when handling certain TCP
    segments. (Issue #5837)

  - An error exists in the handling of corrupted 'Diameter'
    dictionary files that can cause application crashes. 
    (CVE-2011-1958)");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5837");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5876");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5912");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5908");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5934");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-08.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-07.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.17.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.7.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.2.17 / 1.4.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/02");
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
installs = get_kb_list("SMB/Wireshark/*");
if (isnull(installs)) exit(0, "The 'SMB/Wireshark/*' KB items are missing.");

info  = '';
info2 = '';

foreach install(keys(installs))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Wireshark/";

  if (
    version =~ "^1\.2($|\.[0-9]|\.1[0-6])($|[^0-9])" || 
    version =~ "^1\.4($|\.[0-6])($|[^0-9])"
  )  
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version  +
      '\n  Fixed version     : 1.2.17 / 1.4.7\n';
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
